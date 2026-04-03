from django.shortcuts import render, redirect, get_object_or_404
from django.views.generic import ListView, DetailView
from django.contrib.auth.decorators import login_required
from django.http import JsonResponse, HttpResponseBadRequest, HttpResponse
from django.views.decorators.csrf import ensure_csrf_cookie
from django.urls import reverse
import logging
import json
import os
import re
import glob
import csv
from django.contrib import messages
from django.views.decorators.http import require_http_methods
from django.views.decorators.csrf import csrf_exempt
from django.core.paginator import Paginator

from modules.xQuire.models import Firmware
from modules.xScout.services.analysis_service import FirmwareAnalysisService
from modules.xScout.services.extraction_service import FirmwareExtractionService
from modules.xScout.services.components_analysis_service import ComponentsAnalysisService
from modules.xScout.models.mongo_models import FirmwareAnalysisModel
from modules.xScout.models.repositories import FirmwareAnalysisRepository, SecurityAnalysisRepository
from modules.xScout.services.security_analysis_service import SecurityAnalysisService

logger = logging.getLogger(__name__)



def generate_directory_tree(path, max_depth=5, max_files_per_dir=50, rootfs_path=None):
    """
    Generate a directory tree structure for display with special rootfs handling
    """
    def is_on_rootfs_path(current_path):
        """Check if current path is on the way to or inside rootfs"""
        if not rootfs_path:
            return False
        try:
            # Normalize paths for comparison
            current_abs = os.path.abspath(current_path)
            rootfs_abs = os.path.abspath(rootfs_path)
            
            # Check if current path is the rootfs or on the path to rootfs
            return (current_abs == rootfs_abs or 
                    rootfs_abs.startswith(current_abs + os.sep) or
                    current_abs.startswith(rootfs_abs + os.sep))
        except:
            return False
    
    def is_rootfs_directory(current_path):
        """Check if current path is the rootfs directory itself"""
        if not rootfs_path:
            return False
        try:
            return os.path.abspath(current_path) == os.path.abspath(rootfs_path)
        except:
            return False
    
    def is_inside_rootfs(current_path):
        """Check if current path is inside the rootfs directory"""
        if not rootfs_path:
            return False
        try:
            current_abs = os.path.abspath(current_path)
            rootfs_abs = os.path.abspath(rootfs_path)
            return current_abs.startswith(rootfs_abs + os.sep)
        except:
            return False
    
    def build_tree(current_path, current_depth=0):
        if current_depth >= max_depth:
            return None
            
        if not os.path.exists(current_path) or not os.path.isdir(current_path):
            return None
        
        # Determine if this path should be expanded by default
        should_expand = is_on_rootfs_path(current_path)
        is_rootfs = is_rootfs_directory(current_path)
        inside_rootfs = is_inside_rootfs(current_path)
        
        tree = {
            'name': os.path.basename(current_path) or current_path,
            'type': 'directory',
            'children': [],
            'expanded': should_expand,
            'is_rootfs': is_rootfs,
            'inside_rootfs': inside_rootfs
        }
        
        # If we're inside rootfs and not the rootfs itself, only show one level deep
        # and don't expand by default (let user expand manually)
        if inside_rootfs and not is_rootfs:
            tree['expanded'] = False
        
        try:
            items = sorted(os.listdir(current_path))
            file_count = 0
            
            # Separate directories and files
            dirs = []
            files = []
            
            for item in items:
                item_path = os.path.join(current_path, item)
                if os.path.isdir(item_path):
                    dirs.append(item)
                else:
                    files.append(item)
            
            # Add directories first
            for dir_name in dirs:
                dir_path = os.path.join(current_path, dir_name)
                
                # If we're inside rootfs and this is not on the path to deeper rootfs content,
                # just create a simple directory entry without recursing
                if inside_rootfs and not is_rootfs and not is_on_rootfs_path(dir_path):
                    tree['children'].append({
                        'name': dir_name,
                        'type': 'directory',
                        'children': [],
                        'expanded': False,
                        'is_rootfs': False,
                        'inside_rootfs': True
                    })
                else:
                    child_tree = build_tree(dir_path, current_depth + 1)
                    if child_tree:
                        tree['children'].append(child_tree)
                        
            # Add files (limited number)
            for file_name in files[:max_files_per_dir]:
                tree['children'].append({
                    'name': file_name,
                    'type': 'file',
                    'inside_rootfs': inside_rootfs
                })
                file_count += 1
                
            # If there are more files, add a note
            if len(files) > max_files_per_dir:
                tree['children'].append({
                    'name': f'... and {len(files) - max_files_per_dir} more files',
                    'type': 'note'
                })
                
        except PermissionError:
            tree['children'].append({
                'name': '[Permission Denied]',
                'type': 'error'
            })
        except Exception as e:
            tree['children'].append({
                'name': f'[Error: {str(e)}]',
                'type': 'error'
            })
            
        return tree
    
    return build_tree(path)

def index(request):
    """Main page for xScout with comprehensive overview and unified actions"""
    try:
        # Get basic firmware statistics
        firmware_count = Firmware.objects.count()
        recent_firmwares = Firmware.objects.all().order_by('-upload_date')[:10]
        
        # Get analysis service statistics
        analysis_service = FirmwareAnalysisService()
        components_analysis_service = ComponentsAnalysisService()
        security_service = SecurityAnalysisService()
        
        
        # Check extraction and analysis status for each firmware
        firmware_statuses = []
        for firmware in recent_firmwares:
            fw_name = os.path.splitext(os.path.basename(firmware.file.name))[0]
            fw_dir = os.path.dirname(firmware.file.path)
            
            # Get extraction status using utility function
            extraction_status = get_extraction_status(firmware.id)
            is_extracted = extraction_status['is_extracted']
            rootfs_found = extraction_status['rootfs_found']
            
            # Set artifacts directory
            artifacts_dir = os.path.join(fw_dir, "artifacts")
            
            # Check extracted analysis status
            has_components_analysis = False
            if rootfs_found:
                analysis_results = components_analysis_service.get_analysis_results(firmware.id)
                has_components_analysis = analysis_results is not None
            
            # Check security analysis status
            has_security_analysis = security_service.get_security_analysis(firmware.id) is not None
            
            # Check SBOM and vulnerability files
            sbom_path = os.path.join(artifacts_dir, "sbom.json")
            vuln_path = os.path.join(artifacts_dir, "vulnerabilities.json")
            has_sbom = os.path.exists(sbom_path)
            has_vulnerabilities = os.path.exists(vuln_path)
            
            # Get firmware binary analysis status
            fw_binary_analysis = analysis_service.get_latest_analysis_for_firmware(firmware.id)
            has_fw_binary_analysis = fw_binary_analysis is not None and fw_binary_analysis.status == 'completed'
            
            firmware_statuses.append({
                'firmware': firmware,
                'is_extracted': is_extracted,
                'rootfs_found': rootfs_found,
                'has_components_analysis': has_components_analysis,
                'has_security_analysis': has_security_analysis,
                'has_sbom': has_sbom,
                'has_vulnerabilities': has_vulnerabilities,
                'has_fw_binary_analysis': has_fw_binary_analysis,
                'fw_binary_analysis': fw_binary_analysis
            })
            
        
        context = {
            'module_name': 'xScout',
            'module_description': 'Comprehensive Firmware Security Analysis',
            'firmware_count': firmware_count,
            'recent_firmwares': firmware_statuses,
        }
        
        return render(request, 'xScout/index.html', context)
        
    except Exception as e:
        logger.exception("Error loading xScout index")
        context = {
            'module_name': 'xScout',
            'module_description': 'Comprehensive Firmware Security Analysis',
            'firmware_count': 0,
            'error': f"Error loading dashboard: {str(e)}"
        }
        return render(request, 'xScout/index.html', context)

@login_required
@ensure_csrf_cookie
def analyze_firmware(request):
    """Firmware analysis selection and result view"""
    # Get all firmwares from xQuire
    firmwares = Firmware.objects.all().order_by('-upload_date')
    
    # Get analysis service
    analysis_service = FirmwareAnalysisService()
    
    context = {
        'title': 'Analyze Firmware',
        'firmwares': firmwares
    }
    
    # If firmware_id is in GET parameters, show analysis results
    firmware_id = request.GET.get('firmware_id')
    if firmware_id:
        try:
            firmware = Firmware.objects.get(pk=firmware_id)
            context['selected_firmware'] = firmware
            
            # Get latest analysis for this firmware
            analysis = analysis_service.get_latest_analysis_for_firmware(int(firmware_id))
            if analysis:
                context['analysis'] = analysis
                context['analysis_id'] = analysis.id
                context['analysis_status'] = analysis.status
                context['analysis_progress'] = analysis.progress
        except Firmware.DoesNotExist:
            context['error'] = f"Firmware with ID {firmware_id} not found"
    
    return render(request, 'xScout/analyze.html', context)

@login_required
def start_analysis(request):
    """Start a new firmware analysis"""
    if request.method != 'POST':
        return JsonResponse({
            'success': False,
            'message': "Only POST method is allowed"
        }, status=405)
    
    # Get firmware ID from POST data
    firmware_id = request.POST.get('firmware_id')
    
    if not firmware_id:
        return JsonResponse({
            'success': False,
            'message': "Firmware ID is required"
        }, status=400)
    
    try:
        # Get firmware
        firmware = Firmware.objects.get(pk=firmware_id)
        
        # Check if firmware file exists
        if not os.path.exists(firmware.file.path):
            return JsonResponse({
                'success': False,
                'message': f"Firmware file not found: {firmware.file.path}"
            }, status=404)
        
        # Start analysis
        analysis_service = FirmwareAnalysisService()
        analysis_id = analysis_service.analyze_firmware(int(firmware_id))
        
        if analysis_id:
            response_data = {
                'success': True,
                'analysis_id': analysis_id,
                'message': f"Analysis started for {firmware.model.manufacturer.name} {firmware.model.model_number} - {firmware.version}"
            }
            return JsonResponse(response_data)
        else:
            return JsonResponse({
                'success': False,
                'message': "Failed to start analysis. The analysis service returned no ID."
            }, status=500)
    
    except Firmware.DoesNotExist:
        return JsonResponse({
            'success': False,
            'message': f"Firmware with ID {firmware_id} not found"
        }, status=404)
    except Exception as e:
        logger.exception("Error starting analysis")
        return JsonResponse({
            'success': False,
            'message': f"Error: {str(e)}"
        }, status=500)

@login_required
def analysis_status(request, analysis_id):
    """Get status of a firmware analysis"""
    try:
        # Get analysis
        analysis_service = FirmwareAnalysisService()
        analysis = analysis_service.get_analysis(analysis_id)
        
        if analysis:
            return JsonResponse({
                'status': analysis.status,
                'progress': analysis.progress
            })
        else:
            return JsonResponse({
                'status': 'unknown',
                'progress': 0,
                'message': f"Analysis with ID {analysis_id} not found"
            }, status=404)
    
    except Exception as e:
        logger.exception("Error getting analysis status")
        return JsonResponse({
            'status': 'error',
            'progress': 0,
            'message': f"Error: {str(e)}"
        }, status=500)

@login_required
def analysis_results(request, analysis_id):
    """View analysis results"""
    try:
        # Get analysis
        analysis_service = FirmwareAnalysisService()
        analysis = analysis_service.get_analysis(analysis_id)
        
        if not analysis:
            return render(request, 'xScout/error.html', {
                'error': f"Analysis with ID {analysis_id} not found"
            })
        
        # Get firmware
        try:
            firmware = Firmware.objects.get(pk=analysis.firmware_id)
        except Firmware.DoesNotExist:
            firmware = None
        
        context = {
            'title': 'Analysis Results',
            'analysis': analysis,
            'firmware': firmware,
        }
        
        return render(request, 'xScout/results.html', context)
    
    except Exception as e:
        logger.exception("Error viewing analysis results")
        return render(request, 'xScout/error.html', {
            'error': f"Error: {str(e)}"
        })

@login_required
def analysis_list(request):
    """View list of all analyses"""
    try:
        # Get all analyses
        analysis_service = FirmwareAnalysisService()
        analyses = analysis_service.list_analyses()
        
        # Debug information
        logger.info(f"Retrieved {len(analyses)} analyses from MongoDB")
        if not analyses:
            logger.warning("No analyses found in MongoDB")
        else:
            logger.info(f"First analysis: {analyses[0].id} for firmware {analyses[0].firmware_id}")
        
        # Map firmware IDs to Firmware objects
        firmware_map = {}
        firmware_ids = [a.firmware_id for a in analyses]
        logger.info(f"Firmware IDs: {firmware_ids}")
        
        firmwares = Firmware.objects.filter(pk__in=firmware_ids)
        logger.info(f"Found {firmwares.count()} firmwares in the database")
        
        for firmware in firmwares:
            firmware_map[firmware.id] = firmware
            logger.info(f"Added firmware to map: {firmware.id} - {firmware}")
        
        context = {
            'title': 'Analysis Results',
            'analyses': analyses,
            'firmware_map': firmware_map,
            'total_count': len(analyses),
            'completed_count': sum(1 for a in analyses if a.status == 'completed'),
            'failed_count': sum(1 for a in analyses if a.status == 'failed'),
            'running_count': sum(1 for a in analyses if a.status not in ['completed', 'failed'])
        }
        
        return render(request, 'xScout/analysis_list.html', context)
    
    except Exception as e:
        logger.exception("Error listing analyses")
        return render(request, 'xScout/error.html', {
            'error': f"Error: {str(e)}"
        })

@login_required
def delete_analysis(request, analysis_id):
    """Delete a firmware analysis"""
    try:
        # Log request info
        logger.info(f"Delete analysis request: ID={analysis_id}, Method={request.method}")
        
        # Get analysis service
        analysis_service = FirmwareAnalysisService()
        
        # Check if the analysis exists
        analysis = analysis_service.get_analysis(analysis_id)
        
        if not analysis:
            logger.warning(f"Analysis with ID {analysis_id} not found for deletion")
            return JsonResponse({
                'success': False,
                'message': f"Analysis with ID {analysis_id} not found"
            }, status=404)
        
        # Delete the analysis
        logger.info(f"Attempting to delete analysis {analysis_id}")
        success = analysis_service.delete_analysis(analysis_id)
        
        if success:
            logger.info(f"Successfully deleted analysis {analysis_id}")
            if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return JsonResponse({
                    'success': True,
                    'message': f"Analysis {analysis_id} deleted successfully"
                })
            else:
                return redirect('xscout:analysis_list')
        else:
            logger.error(f"Failed to delete analysis {analysis_id}")
            return JsonResponse({
                'success': False,
                'message': f"Failed to delete analysis {analysis_id}"
            }, status=500)
    
    except Exception as e:
        logger.exception("Error deleting analysis")
        return JsonResponse({
            'success': False,
            'message': f"Error: {str(e)}"
        }, status=500)


# ===================================== EXTRACT FIRMWARE ==============================================
# Extraction Utility Functions

def get_extraction_status(firmware_id):
    """
    Get extraction status using xfs utilities
    
    Args:
        firmware_id: ID of the firmware
        
    Returns:
        dict: {
            'is_extracted': bool,
            'extraction_completed': bool,
            'extraction_progress': int,
            'is_running': bool,
            'extraction_dir': str or None,
            'rootfs_found': bool,
            'rootfs_path': str or None
        }
    """
    try:
        firmware = Firmware.objects.get(pk=firmware_id)
        fw_name = os.path.splitext(os.path.basename(firmware.file.name))[0]
        fw_dir = os.path.dirname(firmware.file.path)
        extraction_dir = os.path.join(fw_dir, f"{fw_name}_extract")
        
        # Default values
        result = {
            'is_extracted': False,
            'extraction_completed': False,
            'extraction_progress': 0,
            'is_running': False,
            'extraction_dir': None,
            'rootfs_found': False,
            'rootfs_path': None
        }
        
        # Check if extraction directory exists
        if os.path.exists(extraction_dir):
            result['is_extracted'] = True
            result['extraction_dir'] = extraction_dir
            
            # Check for xfs_results.json (completion indicator)
            xfs_results_path = os.path.join(extraction_dir, "xfs_results.json")
            if os.path.exists(xfs_results_path):
                try:
                    with open(xfs_results_path, 'r') as f:
                        xfs_results = json.load(f)
                    
                    # Extraction is completed
                    result['extraction_completed'] = True
                    result['extraction_progress'] = 100
                    result['is_running'] = False
                    
                    # Check for rootfs
                    identified_rootfs = xfs_results.get('identified_rootfs')
                    if identified_rootfs is not None:
                        result['rootfs_found'] = True
                        result['rootfs_path'] = os.path.join(extraction_dir, identified_rootfs)
                    
                except (json.JSONDecodeError, Exception) as e:
                    logger.error(f"Error reading xfs_results.json: {e}")
            
            # If no completion file, check log for progress
            if not result['extraction_completed']:
                xfs_log_path = os.path.join(extraction_dir, "xfs.log")
                if os.path.exists(xfs_log_path):
                    # Parse log for progress
                    progress, is_running, log_rootfs_found = _parse_xfs_log(xfs_log_path)
                    result['extraction_progress'] = progress
                    result['is_running'] = is_running
                    if log_rootfs_found:
                        result['rootfs_found'] = True
                else:
                    # Extraction started but no progress yet
                    result['extraction_progress'] = 5
                    result['is_running'] = True
        
        return result
        
    except Firmware.DoesNotExist:
        logger.error(f"Firmware with ID {firmware_id} not found")
        return {
            'is_extracted': False,
            'extraction_completed': False,
            'extraction_progress': 0,
            'is_running': False,
            'extraction_dir': None,
            'rootfs_found': False,
            'rootfs_path': None
        }
    except Exception as e:
        logger.error(f"Error getting extraction status for firmware {firmware_id}: {e}")
        return {
            'is_extracted': False,
            'extraction_completed': False,
            'extraction_progress': 0,
            'is_running': False,
            'extraction_dir': None,
            'rootfs_found': False,
            'rootfs_path': None
        }

def check_rootfs(extraction_dir):
    """
    Check for rootfs using xfs results
    
    Args:
        extraction_dir: Path to the extraction directory
        
    Returns:
        tuple: (rootfs_found: bool, rootfs_path: str or None)
    """
    if not os.path.exists(extraction_dir):
        return False, None
    
    xfs_results_path = os.path.join(extraction_dir, "xfs_results.json")
    if os.path.exists(xfs_results_path):
        try:
            with open(xfs_results_path, 'r') as f:
                xfs_results = json.load(f)
            
            identified_rootfs = xfs_results.get('identified_rootfs')
            if identified_rootfs is not None:
                rootfs_path = os.path.join(extraction_dir, identified_rootfs)
                return True, rootfs_path
                
        except (json.JSONDecodeError, Exception) as e:
            logger.error(f"Error reading xfs_results.json: {e}")
    
    return False, None


@login_required
@ensure_csrf_cookie
def extract_firmware(request):
    """Firmware extraction selection view"""
    # Get all firmwares from xQuire
    firmwares = Firmware.objects.all().order_by('-upload_date')
    
    context = {
        'title': 'Extract Firmware',
        'firmwares': firmwares
    }
    
    # If firmware_id is in GET parameters, show selected firmware
    firmware_id = request.GET.get('firmware_id')
    if firmware_id:
        try:
            firmware = Firmware.objects.get(pk=firmware_id)
            context['selected_firmware'] = firmware
            
            # Define paths
            fw_name = os.path.splitext(os.path.basename(firmware.file.name))[0]
            fw_dir = os.path.dirname(firmware.file.path)
            
            logger.info(f"Checking for extraction in {fw_dir} for firmware {fw_name}")
            
            # Get extraction status using utility function
            status = get_extraction_status(firmware_id)
            
            logger.info(f"Extraction status for {fw_name}: completed={status['extraction_completed']}, rootfs_found={status['rootfs_found']}")
            
            # Set context values
            context['rootfs_found'] = status['rootfs_found']
            
            # Get relative rootfs path for display
            if status['rootfs_found'] and status['rootfs_path']:
                # Get the xfs_results.json to find the identified_rootfs
                try:
                    xfs_results_path = os.path.join(status['extraction_dir'], "xfs_results.json")
                    if os.path.exists(xfs_results_path):
                        with open(xfs_results_path, 'r') as f:
                            xfs_results = json.load(f)
                        identified_rootfs = xfs_results.get('identified_rootfs', '')
                        # Extract path after ./xfs-extract/*/
                        if './xfs-extract/' in identified_rootfs:
                            # Find the first / after ./xfs-extract/
                            xfs_extract_index = identified_rootfs.find('./xfs-extract/')
                            after_xfs_extract = identified_rootfs[xfs_extract_index + len('./xfs-extract/'):]
                            # Find the next / to skip the extractor name
                            next_slash = after_xfs_extract.find('/')
                            if next_slash != -1:
                                relative_path = after_xfs_extract[next_slash+1:]
                                context['rootfs_relative_path'] = f"./extracted_files/{relative_path}"
                            else:
                                context['rootfs_relative_path'] = f"./extracted_files/{after_xfs_extract}"
                        else:
                            context['rootfs_relative_path'] = f"./extracted_files/{identified_rootfs}"
                except Exception as e:
                    logger.warning(f"Error getting rootfs relative path: {e}")
                    context['rootfs_relative_path'] = "./extracted_files/squashfs-root"
            
            if status['extraction_completed']:
                context['extraction_completed'] = True
                context['extraction_dir'] = f"{fw_name}_extract"
                
                # Generate directory tree
                try:
                    # Point to extracted_files directory instead of main extraction directory
                    extracted_files_path = os.path.join(status['extraction_dir'], 'extracted_files')
                    if os.path.exists(extracted_files_path):
                        # Get rootfs path for special tree generation
                        rootfs_target_path = None
                        if status['rootfs_found'] and context.get('rootfs_relative_path'):
                            # Convert relative path to absolute for tree generation
                            rel_path = context['rootfs_relative_path'].replace('./extracted_files/', '')
                            rootfs_target_path = os.path.join(extracted_files_path, rel_path)
                        
                        tree_data = generate_directory_tree(extracted_files_path, max_depth=10, max_files_per_dir=50, rootfs_path=rootfs_target_path)
                        context['directory_tree'] = tree_data
                    else:
                        # Fallback to main extraction directory if extracted_files doesn't exist
                        tree_data = generate_directory_tree(status['extraction_dir'])
                        context['directory_tree'] = tree_data
                except Exception as e:
                    logger.warning(f"Failed to generate directory tree: {str(e)}")
                
        except Firmware.DoesNotExist:
            context['error'] = f"Firmware with ID {firmware_id} not found"
        except Exception as e:
            logger.exception(f"Unexpected error in extract_firmware view: {str(e)}")
            context['error'] = f"An unexpected error occurred: {str(e)}"
    
    return render(request, 'xScout/extract.html', context)

@login_required
def start_extraction(request):
    """Start a new firmware extraction"""
    if request.method != 'POST':
        return JsonResponse({
            'success': False,
            'message': "Only POST method is allowed"
        }, status=405)
    
    # Get firmware ID from POST data
    firmware_id = request.POST.get('firmware_id')
    
    if not firmware_id:
        return JsonResponse({
            'success': False,
            'message': "Firmware ID is required"
        }, status=400)
    
    try:
        # Get firmware
        firmware = Firmware.objects.get(pk=firmware_id)
        
        # Check if firmware file exists
        if not os.path.exists(firmware.file.path):
            return JsonResponse({
                'success': False,
                'message': f"Firmware file not found: {firmware.file.path}"
            }, status=404)
        
        # Start extraction
        extraction_service = FirmwareExtractionService()
        success, message = extraction_service.extract_firmware(int(firmware_id))
        
        if success:
            response_data = {
                'success': True,
                'message': f"Extraction started for {firmware.model.manufacturer.name} {firmware.model.model_number} - {firmware.version}"
            }
            return JsonResponse(response_data)
        else:
            return JsonResponse({
                'success': False,
                'message': f"Failed to start extraction: {message}"
            }, status=500)
    
    except Firmware.DoesNotExist:
        return JsonResponse({
            'success': False,
            'message': f"Firmware with ID {firmware_id} not found"
        }, status=404)
    except Exception as e:
        logger.exception("Error starting extraction")
        return JsonResponse({
            'success': False,
            'message': f"Error: {str(e)}"
        }, status=500)

@login_required
def check_extraction_status(request, firmware_id):
    """Check the status of a firmware extraction using xfs"""
    try:
        # Get extraction status using utility function
        status = get_extraction_status(firmware_id)
        
        # Log the check
        firmware = Firmware.objects.get(pk=firmware_id)
        fw_name = os.path.splitext(os.path.basename(firmware.file.name))[0]
        logger.info(f"Checking extraction status for {fw_name}: progress={status['extraction_progress']}%, running={status['is_running']}, rootfs_found={status['rootfs_found']}")
        
        # Return the current status
        return JsonResponse({
            'status': 'running' if status['is_running'] else 'completed' if status['extraction_completed'] else 'partial',
            'extraction_completed': status['extraction_completed'],
            'rootfs_found': status['rootfs_found'],
            'extraction_progress': status['extraction_progress'],
            'is_running': status['is_running'],
            'extraction_dir': f"{fw_name}_extract" if status['is_extracted'] else None
        })
        
    except Exception as e:
        logger.exception(f"Error checking extraction status for {firmware_id}")
        return JsonResponse({
            'status': 'error',
            'error': str(e)
        }, status=500)

def _parse_xfs_log(log_path):
        """
        Parse xfs log file to determine extraction progress
        
        Args:
            log_path: Path to the xfs log file
            
        Returns:
            Tuple[int, bool, bool]: (progress_percentage, is_running, rootfs_found)
        """
        try:
            with open(log_path, 'r') as f:
                log_content = f.read()
            
            lines = log_content.strip().split('\n')
            max_stage = 0
            is_running = True
            rootfs_found = False
            
            for line in lines:
                line = line.strip()
                
                # Check for stage completion
                if '[STAGE' in line:
                    # Extract stage number
                    stage_match = re.search(r'\[STAGE (\d+)/4\]', line)
                    if stage_match:
                        stage_num = int(stage_match.group(1))
                        max_stage = max(max_stage, stage_num)
                
                # Check for rootfs found
                if 'rootfs found at:' in line or 'identify rootfs: found' in line:
                    rootfs_found = True
                
                # Check for completion
                if 'Process complete' in line or '[STAGE 4/4]' in line:
                    max_stage = 4
                    is_running = False
            
            # Calculate progress based on max stage reached
            if max_stage == 0:
                progress = 5  # Started but no stage completed
            elif max_stage == 1:
                progress = 25  # Stage 1 completed
            elif max_stage == 2:
                progress = 50  # Stage 2 completed
            elif max_stage == 3:
                progress = 75  # Stage 3 completed
            elif max_stage == 4:
                progress = 100  # Stage 4 completed
                is_running = False
            else:
                progress = 0
            
            # If process is complete but we haven't seen stage 4, set to 100%
            if not is_running and progress < 100:
                progress = 100
            
            return progress, is_running, rootfs_found
            
        except Exception as e:
            logger.error(f"Error parsing xfs log file {log_path}: {e}")
            return 0, False, False
        



# ===================================== COMPONENTS ANALYSIS ==============================================

@login_required
@ensure_csrf_cookie
def components_analysis(request, firmware_id=None):
    """View for components analysis"""
    # Get all firmwares from xQuire
    firmwares = Firmware.objects.all().order_by('-upload_date')
    
    context = {
        'title': 'Components Analysis',
        'firmwares': firmwares
    }
    
    # Get firmware_id from URL parameter or GET parameter
    if firmware_id is None:
        firmware_id = request.GET.get('firmware_id')
    if firmware_id:
        try:
            firmware = Firmware.objects.get(pk=firmware_id)
            context['firmware'] = firmware
            
            # Get extraction service
            components_analysis_service = ComponentsAnalysisService()
            
            # Get extraction status using xfs utilities
            extraction_status = get_extraction_status(firmware_id)
            
            if extraction_status['extraction_completed']:
                context['extraction_exists'] = True
                context['extraction_dir'] = os.path.basename(extraction_status['extraction_dir'])
                logger.info(f"Extraction directory found: {extraction_status['extraction_dir']}")
                
                # Check for rootfs using xfs utilities
                if extraction_status['rootfs_found']:
                    context['rootfs_exists'] = True
                    
                    # Get artifacts directory
                    artifacts_dir = components_analysis_service.get_artifacts_path(int(firmware_id))
                    
                    # Check for SBOM file
                    sbom_path = os.path.join(artifacts_dir, "sbom.json")
                    if os.path.exists(sbom_path):
                        context['sbom_exists'] = True
                        
                        # Load SBOM summary if available
                        try:
                            with open(sbom_path, 'r') as f:
                                sbom_data = json.load(f)
                                context['sbom_summary'] = {
                                    'total_packages': len(sbom_data.get('artifacts', [])),
                                    'file_path': sbom_path
                                }
                        except Exception as e:
                            logger.error(f"Error loading SBOM data: {e}")
                    
                    # Check for vulnerability files
                    vuln_path = os.path.join(artifacts_dir, "vulnerabilities.json")
                    vuln_summary_path = os.path.join(artifacts_dir, "vulnerability_summary.json")
                    
                    if os.path.exists(vuln_path) and os.path.exists(vuln_summary_path):
                        context['vulnerabilities_exist'] = True
                        
                        # Load vulnerability summary
                        try:
                            with open(vuln_summary_path, 'r') as f:
                                vuln_summary = json.load(f)
                                context['vulnerability_summary'] = vuln_summary
                        except Exception as e:
                            logger.error(f"Error loading vulnerability summary: {e}")
                    
            else:
                context['extraction_exists'] = False
                if not extraction_status['is_extracted']:
                    context['error'] = f"No extraction directory found for this firmware. Please extract the firmware first."
                else:
                    context['error'] = f"Extraction is not yet completed. Please wait for extraction to finish."
            
            # Check for error in query parameters (from redirect)
            if request.GET.get('error'):
                context['error'] = request.GET.get('error')
            
            # Get analysis results if available
            analysis_results = components_analysis_service.get_analysis_results(int(firmware_id))
            if analysis_results:
                context['analysis_results'] = analysis_results
            
            # Get security analysis results if available
            security_results = components_analysis_service.get_security_analysis_results(int(firmware_id))
            if security_results:
                context['security_results'] = security_results
            
        except Firmware.DoesNotExist:
            context['error'] = f"Firmware with ID {firmware_id} not found"
    
    return render(request, 'xScout/components_analysis.html', context)

@login_required
def start_components_analysis(request):
    """Start a new components analysis"""
    if request.method != 'POST':
        return JsonResponse({
            'success': False,
            'message': "Only POST method is allowed"
        }, status=405)
    
    # Get firmware ID from POST data
    firmware_id = request.POST.get('firmware_id')
    
    if not firmware_id:
        return JsonResponse({
            'success': False,
            'message': "Firmware ID is required"
        }, status=400)
    
    try:
        # Get firmware
        firmware = Firmware.objects.get(pk=firmware_id)
        
        # Start analysis
        components_analysis_service = ComponentsAnalysisService()
        
        # Check if extraction is completed using xfs utilities
        extraction_status = get_extraction_status(firmware_id)
        if not extraction_status['extraction_completed']:
            if not extraction_status['is_extracted']:
                message = "No extraction directory found for this firmware. Please extract the firmware first."
            else:
                message = "Extraction is not yet completed. Please wait for extraction to finish."
            return JsonResponse({
                'success': False,
                'message': message
            }, status=400)
        
        # Run analysis
        analysis_results = components_analysis_service.analyze_extracted_firmware(int(firmware_id))
        
        if analysis_results:
            # Redirect to the extracted analysis page instead of returning JSON
            return redirect('xscout:firmware_analysis_detail', firmware_id=firmware_id)
        else:
            # If analysis fails, show an error message on the extracted analysis page
            return redirect('xscout:firmware_analysis_detail', firmware_id=firmware_id)
    
    except Firmware.DoesNotExist:
        return JsonResponse({
            'success': False,
            'message': f"Firmware with ID {firmware_id} not found"
        }, status=404)
    except Exception as e:
        logger.exception("Error starting components analysis")
        return JsonResponse({
            'success': False,
            'message': f"Error: {str(e)}"
        }, status=500)

@login_required
def generate_sbom(request):
    """Generate SBOM for extracted firmware"""
    if request.method != 'POST':
        return JsonResponse({
            'success': False,
            'message': "Only POST method is allowed"
        }, status=405)
    
    # Get firmware ID from POST data
    firmware_id = request.POST.get('firmware_id')
    
    if not firmware_id:
        return JsonResponse({
            'success': False,
            'message': "Firmware ID is required"
        }, status=400)
    
    try:
        # Get firmware
        firmware = Firmware.objects.get(pk=firmware_id)
        
        # Generate SBOM
        components_analysis_service = ComponentsAnalysisService()
        sbom_results = components_analysis_service.generate_sbom(int(firmware_id))
        
        if sbom_results.get('success'):
            return JsonResponse({
                'success': True,
                'message': f"SBOM generated successfully for {firmware.model.manufacturer.name} {firmware.model.model_number} - {firmware.version}",
                'sbom_file': sbom_results.get('sbom_file'),
                'total_packages': sbom_results.get('total_packages', 0)
            })
        else:
            return JsonResponse({
                'success': False,
                'message': sbom_results.get('error', 'Failed to generate SBOM')
            }, status=500)
    
    except Firmware.DoesNotExist:
        return JsonResponse({
            'success': False,
            'message': f"Firmware with ID {firmware_id} not found"
        }, status=404)
    except Exception as e:
        logger.exception("Error generating SBOM")
        return JsonResponse({
            'success': False,
            'message': f"Error: {str(e)}"
        }, status=500)

@login_required
def check_vulnerabilities(request):
    """Check vulnerabilities for extracted firmware"""
    if request.method != 'POST':
        return JsonResponse({
            'success': False,
            'message': "Only POST method is allowed"
        }, status=405)
    
    # Get firmware ID from POST data
    firmware_id = request.POST.get('firmware_id')
    
    if not firmware_id:
        return JsonResponse({
            'success': False,
            'message': "Firmware ID is required"
        }, status=400)
    
    try:
        # Get firmware
        firmware = Firmware.objects.get(pk=firmware_id)
        
        # Check vulnerabilities
        components_analysis_service = ComponentsAnalysisService()
        vuln_results = components_analysis_service.check_vulnerabilities(int(firmware_id))
        
        if vuln_results.get('success'):
            summary = vuln_results.get('summary', {})
            return JsonResponse({
                'success': True,
                'message': f"Vulnerability analysis completed for {firmware.model.manufacturer.name} {firmware.model.model_number} - {firmware.version}",
                'vulnerability_file': vuln_results.get('vulnerability_file'),
                'summary_file': vuln_results.get('summary_file'),
                'total_vulnerabilities': summary.get('total_vulnerabilities', 0),
                'critical_count': summary.get('severity_counts', {}).get('critical', 0),
                'high_count': summary.get('severity_counts', {}).get('high', 0)
            })
        else:
            return JsonResponse({
                'success': False,
                'message': vuln_results.get('error', 'Failed to check vulnerabilities')
            }, status=500)
    
    except Firmware.DoesNotExist:
        return JsonResponse({
            'success': False,
            'message': f"Firmware with ID {firmware_id} not found"
        }, status=404)
    except Exception as e:
        logger.exception("Error checking vulnerabilities")
        return JsonResponse({
            'success': False,
            'message': f"Error: {str(e)}"
        }, status=500)

@login_required
def run_security_analysis(request):
    """Run full security analysis (SBOM + vulnerabilities) for extracted firmware"""
    if request.method != 'POST':
        return JsonResponse({
            'success': False,
            'message': "Only POST method is allowed"
        }, status=405)
    
    # Get firmware ID from POST data
    firmware_id = request.POST.get('firmware_id')
    
    if not firmware_id:
        return JsonResponse({
            'success': False,
            'message': "Firmware ID is required"
        }, status=400)
    
    try:
        # Get firmware
        firmware = Firmware.objects.get(pk=firmware_id)
        
        # Run full security analysis
        components_analysis_service = ComponentsAnalysisService()
        security_results = components_analysis_service.run_full_security_analysis(int(firmware_id))
        
        if security_results.get('success'):
            sbom_results = security_results.get('sbom_results', {})
            vuln_results = security_results.get('vulnerability_results', {})
            vuln_summary = vuln_results.get('summary', {})
            
            return JsonResponse({
                'success': True,
                'message': f"Security analysis completed for {firmware.model.manufacturer.name} {firmware.model.model_number} - {firmware.version}",
                'sbom_packages': sbom_results.get('total_packages', 0),
                'total_vulnerabilities': vuln_summary.get('total_vulnerabilities', 0),
                'critical_count': vuln_summary.get('severity_counts', {}).get('critical', 0),
                'high_count': vuln_summary.get('severity_counts', {}).get('high', 0)
            })
        else:
            return JsonResponse({
                'success': False,
                'message': security_results.get('error', 'Failed to run security analysis')
            }, status=500)
    
    except Firmware.DoesNotExist:
        return JsonResponse({
            'success': False,
            'message': f"Firmware with ID {firmware_id} not found"
        }, status=404)
    except Exception as e:
        logger.exception("Error running security analysis")
        return JsonResponse({
            'success': False,
            'message': f"Error: {str(e)}"
        }, status=500)

# Security Analysis Views

def security_dashboard(request):
    """Security dashboard with overview of all firmwares"""
    try:
        security_service = SecurityAnalysisService()
        
        # Get all dashboard data and statistics in one call
        dashboard_context = security_service.get_dashboard_data_with_stats(limit=100)
        
        # Add template-specific context
        context = {
            **dashboard_context,
            'overview': dashboard_context.get('dashboard_data', {}).get('overview', {}),
            'recent_analyses': dashboard_context.get('dashboard_data', {}).get('recent_analyses', []),
            'risk_distribution': dashboard_context.get('dashboard_data', {}).get('risk_distribution', {})
        }
        
        return render(request, 'xScout/security_dashboard.html', context)
        
    except Exception as e:
        logger.error(f"Error in security dashboard: {str(e)}")
        # Return minimal error context
        context = {
            'dashboard_data': {},
            'stats': {
                'total_security_analyses': 0,
                'total_firmwares': 0,
                'high_risk_firmwares': 0,
                'medium_risk_firmwares': 0,
                'low_risk_firmwares': 0,
                'total_vulnerabilities': 0,
                'critical_vulnerabilities': 0,
                'high_vulnerabilities': 0,
                'total_packages': 0,
                'avg_risk_score': 0
            },
            'security_analyses': [],
            'has_analyses': False,
            'error': str(e),
            'overview': {},
            'recent_analyses': [],
            'risk_distribution': {}
        }
        return render(request, 'xScout/security_dashboard.html', context)

def delete_security_analysis(request, firmware_id):
    """Delete security analysis for a specific firmware"""
    if request.method == 'POST':
        try:
            # Validate firmware_id
            if not firmware_id or firmware_id <= 0:
                messages.error(request, f"Invalid firmware ID: {firmware_id}")
                return redirect('xscout:security_dashboard')
            
            security_service = SecurityAnalysisService()
            
            # Check if security analysis exists
            analysis = security_service.get_security_analysis(firmware_id)
            if not analysis:
                messages.error(request, f"No security analysis found for firmware ID {firmware_id}")
                return redirect('xscout:security_dashboard')
            
            # Get firmware info for the success message
            firmware_info = analysis.firmware_info
            firmware_name = f"{firmware_info.get('manufacturer', 'Unknown')} {firmware_info.get('model', 'Unknown')} v{firmware_info.get('version', 'Unknown')}"
            
            logger.info(f"Attempting to delete security analysis for firmware {firmware_id} ({firmware_name})")
            
            # Delete the analysis
            success = security_service.delete_security_analysis(firmware_id)
            
            if success:
                messages.success(request, f"Successfully deleted security analysis for {firmware_name}")
                logger.info(f"Successfully deleted security analysis for firmware {firmware_id}")
            else:
                messages.error(request, f"Failed to delete security analysis for {firmware_name}")
                logger.error(f"Failed to delete security analysis for firmware {firmware_id}")
                
        except Exception as e:
            logger.error(f"Error deleting security analysis for firmware {firmware_id}: {str(e)}")
            messages.error(request, f"Error deleting security analysis: {str(e)}")
    else:
        messages.error(request, "Invalid request method. Only POST requests are allowed for deletion.")
    
    return redirect('xscout:security_dashboard')

def security_analysis_detail(request, firmware_id):
    """Detailed security analysis view with SBOM and vulnerabilities"""
    firmware = get_object_or_404(Firmware, pk=firmware_id)
    
    try:
        security_service = SecurityAnalysisService()
        security_analysis = security_service.get_security_analysis(firmware_id)
        
        if not security_analysis:
            messages.warning(request, "No security analysis found for this firmware. Please run security analysis first.")
            return redirect('xscout:firmware_analysis_detail', firmware_id=firmware_id)
        
        # Process data for display
        sbom_data = security_analysis.sbom_data
        vulnerability_data = security_analysis.vulnerability_data
        security_summary = security_analysis.security_summary
        
        # Paginate packages and vulnerabilities
        packages = sbom_data.get('packages', [])
        vulnerabilities = vulnerability_data.get('vulnerabilities', [])
        
        # Package pagination
        package_paginator = Paginator(packages, 20)
        package_page = request.GET.get('package_page', 1)
        packages_page_obj = package_paginator.get_page(package_page)
        
        # Vulnerability pagination
        vuln_paginator = Paginator(vulnerabilities, 10)
        vuln_page = request.GET.get('vuln_page', 1)
        vulns_page_obj = vuln_paginator.get_page(vuln_page)
        
        context = {
            'firmware': firmware,
            'security_analysis': security_analysis,
            'sbom_data': sbom_data,
            'vulnerability_data': vulnerability_data,
            'security_summary': security_summary,
            'packages_page_obj': packages_page_obj,
            'vulns_page_obj': vulns_page_obj,
            'severity_counts': vulnerability_data.get('severity_counts', {}),
            'package_types': security_summary.get('package_types', {}),
        }
        
        return render(request, 'xScout/security_analysis_detail.html', context)
        
    except Exception as e:
        logger.error(f"Error loading security analysis: {str(e)}")
        messages.error(request, f"Error loading security analysis: {str(e)}")
        return redirect('xquire:firmware_detail', pk=firmware_id)

def sbom_viewer(request, firmware_id):
    """Enhanced SBOM viewer with package details, filtering, and export"""
    firmware = get_object_or_404(Firmware, pk=firmware_id)
    
    try:
        security_service = SecurityAnalysisService()
        security_analysis = security_service.get_security_analysis(firmware_id)
        
        if not security_analysis:
            messages.warning(request, "No SBOM data found for this firmware. Please run security analysis first.")
            return redirect('xscout:firmware_analysis_detail', firmware_id=firmware_id)
        
        sbom_data = security_analysis.sbom_data
        packages = sbom_data.get('packages', [])
        
        # Get all unique values for filters
        all_package_types = sorted(list(set(pkg.get('type', 'unknown') for pkg in packages)))
        all_suppliers = sorted(list(set(pkg.get('supplier', '') for pkg in packages if pkg.get('supplier', ''))))
        
        # Apply filters
        search_query = request.GET.get('search', '')
        package_type_filter = request.GET.get('type', '')
        supplier_filter = request.GET.get('supplier', '')
        version_filter = request.GET.get('version_status', '')  # 'versioned', 'unversioned', or ''
        purl_filter = request.GET.get('purl_status', '')  # 'has_purl', 'no_purl', or ''
        
        # Filter by search query
        if search_query:
            packages = [
                pkg for pkg in packages 
                if search_query.lower() in pkg.get('name', '').lower() or 
                   search_query.lower() in pkg.get('type', '').lower() or
                   search_query.lower() in pkg.get('supplier', '').lower() or
                   search_query.lower() in pkg.get('purl', '').lower()
            ]
        
        # Filter by package type
        if package_type_filter:
            packages = [pkg for pkg in packages if pkg.get('type', '') == package_type_filter]
        
        # Filter by supplier
        if supplier_filter:
            packages = [pkg for pkg in packages if pkg.get('supplier', '') == supplier_filter]
        
        # Filter by version status
        if version_filter == 'versioned':
            packages = [pkg for pkg in packages if pkg.get('version', '')]
        elif version_filter == 'unversioned':
            packages = [pkg for pkg in packages if not pkg.get('version', '')]
        
        # Filter by PURL status
        if purl_filter == 'has_purl':
            packages = [pkg for pkg in packages if pkg.get('purl', '')]
        elif purl_filter == 'no_purl':
            packages = [pkg for pkg in packages if not pkg.get('purl', '')]
        
        # Sort packages
        sort_by = request.GET.get('sort', 'name')
        reverse_sort = request.GET.get('reverse', 'false') == 'true'
        
        if sort_by in ['name', 'version', 'type', 'supplier']:
            packages.sort(key=lambda x: (x.get(sort_by, '') or '').lower(), reverse=reverse_sort)
        
        # Check for export request
        export_format = request.GET.get('export', '')
        if export_format == 'csv':
            return export_sbom_csv(packages, firmware)
        
        # Pagination
        page_size = int(request.GET.get('page_size', 25))
        paginator = Paginator(packages, page_size)
        page_number = request.GET.get('page')
        page_obj = paginator.get_page(page_number)
        
        # Calculate statistics
        stats = {
            'total_packages': len(sbom_data.get('packages', [])),
            'filtered_count': len(packages),
            'binaries': len([p for p in packages if p.get('type') == 'binary']),
            'kernel_modules': len([p for p in packages if p.get('type') == 'linux-kernel-module']),
            'versioned': len([p for p in packages if p.get('version', '')]),
            'with_purl': len([p for p in packages if p.get('purl', '')]),
        }
        
        # Build filter summary for display
        active_filters = []
        if search_query:
            active_filters.append(f'Search: "{search_query}"')
        if package_type_filter:
            active_filters.append(f'Type: {package_type_filter}')
        if supplier_filter:
            active_filters.append(f'Supplier: {supplier_filter}')
        if version_filter:
            active_filters.append(f'Version: {version_filter}')
        if purl_filter:
            active_filters.append(f'PURL: {purl_filter}')
        
        context = {
            'firmware': firmware,
            'firmware_id': firmware_id,
            'security_analysis': security_analysis,
            'sbom_data': sbom_data,
            'page_obj': page_obj,
            'packages': page_obj.object_list,
            'stats': stats,
            'search_query': search_query,
            'package_type_filter': package_type_filter,
            'supplier_filter': supplier_filter,
            'version_filter': version_filter,
            'purl_filter': purl_filter,
            'sort_by': sort_by,
            'reverse_sort': reverse_sort,
            'page_size': page_size,
            'package_types': all_package_types,
            'suppliers': all_suppliers,
            'active_filters': active_filters,
            'has_filters': len(active_filters) > 0,
        }
        
        return render(request, 'xScout/sbom_viewer.html', context)
        
    except Exception as e:
        logger.error(f"Error loading SBOM viewer: {str(e)}")
        messages.error(request, f"Error loading SBOM data: {str(e)}")
        return redirect('xquire:firmware_detail', pk=firmware_id)

def export_sbom_csv(packages, firmware):
    """Export SBOM packages to CSV format"""
    try:
        # Create HTTP response with CSV content type
        response = HttpResponse(content_type='text/csv')
        filename = f"sbom_{firmware.model.manufacturer.name}_{firmware.model.model_number}_{firmware.version}.csv"
        filename = filename.replace(' ', '_').replace('/', '_')
        response['Content-Disposition'] = f'attachment; filename="{filename}"'
        
        # Create CSV writer
        writer = csv.writer(response)
        
        # Write header
        writer.writerow([
            'Package Name',
            'Version',
            'Type',
            'Supplier',
            'PURL',
            'CPEs',
            'License',
            'Locations'
        ])
        
        # Write package data
        for pkg in packages:
            writer.writerow([
                pkg.get('name', ''),
                pkg.get('version', 'N/A'),
                pkg.get('type', 'unknown'),
                pkg.get('supplier', 'N/A'),
                pkg.get('purl', 'N/A'),
                ', '.join(pkg.get('cpes', [])) if pkg.get('cpes') else 'N/A',
                pkg.get('license_declared', 'N/A'),
                ', '.join(pkg.get('locations', [])[:3]) if pkg.get('locations') else 'N/A'  # Limit to 3 locations for readability
            ])
        
        return response
        
    except Exception as e:
        logger.error(f"Error exporting SBOM to CSV: {str(e)}")
        response = HttpResponse("Error generating CSV export", status=500)
        return response

def vulnerability_viewer(request, firmware_id):
    """Enhanced vulnerability viewer with CVE details, EPSS, and SBOM integration"""
    firmware = get_object_or_404(Firmware, pk=firmware_id)
    
    try:
        security_service = SecurityAnalysisService()
        security_analysis = security_service.get_security_analysis(firmware_id)
        
        if not security_analysis:
            messages.warning(request, "No vulnerability data found for this firmware. Please run security analysis first.")
            return redirect('xscout:firmware_analysis_detail', firmware_id=firmware_id)
        
        vulnerability_data = security_analysis.vulnerability_data
        all_vulnerabilities = vulnerability_data.get('vulnerabilities', [])
        vulnerabilities = all_vulnerabilities.copy()
        
        # Apply filters
        search_query = request.GET.get('search', '')
        severity_filter = request.GET.get('severity', '')
        package_filter = request.GET.get('package', '')
        epss_filter = request.GET.get('epss', '')  # 'high', 'medium', 'low'
        exploitability_filter = request.GET.get('exploitability', '')  # 'high', 'medium', 'low'
        fix_filter = request.GET.get('fix_status', '')  # 'fixed', 'not-fixed', 'unknown'
        package_type_filter = request.GET.get('package_type', '')  # From SBOM
        
        if search_query:
            vulnerabilities = [
                vuln for vuln in vulnerabilities 
                if search_query.lower() in vuln.get('cve_id', '').lower() or 
                   search_query.lower() in vuln.get('description', '').lower() or
                   search_query.lower() in vuln.get('package_name', '').lower()
            ]
        
        if severity_filter:
            vulnerabilities = [vuln for vuln in vulnerabilities if vuln.get('severity', '') == severity_filter]
        
        if package_filter:
            vulnerabilities = [vuln for vuln in vulnerabilities if package_filter.lower() in vuln.get('package_name', '').lower()]
        
        # EPSS filter
        if epss_filter == 'high':  # >50% probability
            vulnerabilities = [vuln for vuln in vulnerabilities if vuln.get('epss_probability', 0) > 0.5]
        elif epss_filter == 'medium':  # 10-50%
            vulnerabilities = [vuln for vuln in vulnerabilities if 0.1 <= vuln.get('epss_probability', 0) <= 0.5]
        elif epss_filter == 'low':  # <10%
            vulnerabilities = [vuln for vuln in vulnerabilities if vuln.get('epss_probability', 0) < 0.1]
        
        # Exploitability filter
        if exploitability_filter == 'high':  # >7
            vulnerabilities = [vuln for vuln in vulnerabilities if vuln.get('exploitability_score', 0) > 7]
        elif exploitability_filter == 'medium':  # 4-7
            vulnerabilities = [vuln for vuln in vulnerabilities if 4 <= vuln.get('exploitability_score', 0) <= 7]
        elif exploitability_filter == 'low':  # <4
            vulnerabilities = [vuln for vuln in vulnerabilities if vuln.get('exploitability_score', 0) < 4]
        
        # Fix availability filter
        if fix_filter == 'fixed':
            vulnerabilities = [vuln for vuln in vulnerabilities if vuln.get('fix_state') == 'fixed']
        elif fix_filter == 'not-fixed':
            vulnerabilities = [vuln for vuln in vulnerabilities if vuln.get('fix_state') in ['not-fixed', 'wont-fix']]
        elif fix_filter == 'unknown':
            vulnerabilities = [vuln for vuln in vulnerabilities if vuln.get('fix_state') == 'unknown']
        
        # Package type filter (from SBOM)
        if package_type_filter:
            vulnerabilities = [vuln for vuln in vulnerabilities if vuln.get('sbom_package_type', '') == package_type_filter]
        
        # Sort vulnerabilities
        sort_by = request.GET.get('sort', 'risk_score')
        reverse_sort = request.GET.get('reverse', 'true') == 'true'
        
        if sort_by in ['cvss_score', 'risk_score', 'epss_probability', 'exploitability_score', 'impact_score']:
            vulnerabilities.sort(key=lambda x: x.get(sort_by, 0), reverse=reverse_sort)
        elif sort_by == 'cve_year':
            vulnerabilities.sort(key=lambda x: x.get('cve_year', 0), reverse=reverse_sort)
        elif sort_by in ['cve_id', 'severity', 'package_name']:
            vulnerabilities.sort(key=lambda x: x.get(sort_by, ''), reverse=reverse_sort)
        
        # Calculate enhanced statistics
        stats = {
            'total_vulnerabilities': len(all_vulnerabilities),
            'filtered_count': len(vulnerabilities),
            
            # Exploitability analysis
            'highly_exploitable': len([v for v in all_vulnerabilities if v.get('epss_probability', 0) > 0.5 or v.get('exploitability_score', 0) > 7]),
            'weaponized': len([v for v in all_vulnerabilities if v.get('epss_probability', 0) > 0.9]),
            'avg_epss': sum(v.get('epss_probability', 0) for v in all_vulnerabilities) / len(all_vulnerabilities) if all_vulnerabilities else 0,
            'avg_exploitability': sum(v.get('exploitability_score', 0) for v in all_vulnerabilities) / len(all_vulnerabilities) if all_vulnerabilities else 0,
            
            # Fix statistics
            'fixable': len([v for v in all_vulnerabilities if v.get('fix_state') == 'fixed']),
            'unfixable': len([v for v in all_vulnerabilities if v.get('fix_state') in ['not-fixed', 'wont-fix']]),
            'fix_unknown': len([v for v in all_vulnerabilities if v.get('fix_state') == 'unknown']),
            
            # Risk distribution
            'critical_risk': len([v for v in all_vulnerabilities if v.get('risk_score', 0) > 9]),
            'high_risk': len([v for v in all_vulnerabilities if 7 <= v.get('risk_score', 0) <= 9]),
            'medium_risk': len([v for v in all_vulnerabilities if 4 <= v.get('risk_score', 0) < 7]),
            'low_risk': len([v for v in all_vulnerabilities if v.get('risk_score', 0) < 4]),
            
            # Package type breakdown
            'binary_vulnerabilities': len([v for v in all_vulnerabilities if v.get('sbom_package_type', '') == 'binary']),
            'kernel_module_vulnerabilities': len([v for v in all_vulnerabilities if v.get('sbom_package_type', '') == 'linux-kernel-module']),
            
            # Age analysis
            'ancient': len([v for v in all_vulnerabilities if 0 < v.get('cve_year', 9999) < 2015]),
            'old': len([v for v in all_vulnerabilities if 2015 <= v.get('cve_year', 0) < 2020]),
            'recent': len([v for v in all_vulnerabilities if 2020 <= v.get('cve_year', 0) < 2024]),
            'new': len([v for v in all_vulnerabilities if v.get('cve_year', 0) >= 2024]),
        }
        
        stats['fix_available_percentage'] = (stats['fixable'] / stats['total_vulnerabilities'] * 100) if stats['total_vulnerabilities'] > 0 else 0
        
        # Create remediation action list
        remediation_actions = {}
        for vuln in all_vulnerabilities:
            if vuln.get('fix_state') == 'fixed' and vuln.get('suggested_version'):
                pkg_name = vuln.get('package_name', '')
                current_version = vuln.get('package_version', '')
                suggested_version = vuln.get('suggested_version', '')
                
                key = f"{pkg_name}:{current_version}:{suggested_version}"
                if key not in remediation_actions:
                    remediation_actions[key] = {
                        'package_name': pkg_name,
                        'current_version': current_version,
                        'suggested_version': suggested_version,
                        'locations': vuln.get('sbom_locations', []),
                        'package_type': vuln.get('sbom_package_type', ''),
                        'vulnerabilities': [],
                        'severity_counts': {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'negligible': 0}
                    }
                
                remediation_actions[key]['vulnerabilities'].append({
                    'cve_id': vuln.get('cve_id', ''),
                    'severity': vuln.get('severity', ''),
                    'risk_score': vuln.get('risk_score', 0)
                })
                
                severity = vuln.get('severity', 'unknown')
                if severity in remediation_actions[key]['severity_counts']:
                    remediation_actions[key]['severity_counts'][severity] += 1
        
        # Sort remediation actions by total severity
        remediation_list = sorted(
            remediation_actions.values(),
            key=lambda x: (x['severity_counts']['critical'] * 10 + x['severity_counts']['high'] * 5 + x['severity_counts']['medium'] * 2),
            reverse=True
        )
        
        # Get top priority vulnerabilities (high EPSS or high risk score)
        top_priority = sorted(
            all_vulnerabilities,
            key=lambda x: (x.get('risk_score', 0) * 10 + x.get('epss_probability', 0) * 100),
            reverse=True
        )[:10]
        
        # Pagination
        paginator = Paginator(vulnerabilities, 15)
        page_number = request.GET.get('page')
        page_obj = paginator.get_page(page_number)
        
        # Get filter options
        all_severities = sorted(list(set(vuln.get('severity', 'unknown') for vuln in all_vulnerabilities)))
        all_packages = sorted(list(set(vuln.get('package_name', 'unknown') for vuln in all_vulnerabilities)))
        all_package_types = sorted(list(set(vuln.get('sbom_package_type', 'unknown') for vuln in all_vulnerabilities if vuln.get('sbom_package_type'))))
        
        # Build active filters list
        active_filters = []
        if search_query:
            active_filters.append(f'Search: "{search_query}"')
        if severity_filter:
            active_filters.append(f'Severity: {severity_filter}')
        if package_filter:
            active_filters.append(f'Package: {package_filter}')
        if epss_filter:
            active_filters.append(f'EPSS: {epss_filter}')
        if exploitability_filter:
            active_filters.append(f'Exploitability: {exploitability_filter}')
        if fix_filter:
            active_filters.append(f'Fix Status: {fix_filter}')
        if package_type_filter:
            active_filters.append(f'Package Type: {package_type_filter}')
        
        context = {
            'firmware': firmware,
            'firmware_id': firmware_id,
            'security_analysis': security_analysis,
            'vulnerability_data': vulnerability_data,
            'page_obj': page_obj,
            'vulnerabilities': page_obj.object_list,
            'stats': stats,
            'remediation_list': remediation_list[:20],  # Top 20 remediation actions
            'top_priority': top_priority,
            
            # Filters
            'search_query': search_query,
            'severity_filter': severity_filter,
            'package_filter': package_filter,
            'epss_filter': epss_filter,
            'exploitability_filter': exploitability_filter,
            'fix_filter': fix_filter,
            'package_type_filter': package_type_filter,
            'sort_by': sort_by,
            'reverse_sort': reverse_sort,
            
            # Filter options
            'severities': all_severities,
            'packages': all_packages,
            'package_types': all_package_types,
            'active_filters': active_filters,
            'has_filters': len(active_filters) > 0,
            
            # Legacy compatibility
            'severity_counts': vulnerability_data.get('severity_counts', {}),
            'total_vulnerabilities': len(all_vulnerabilities),
            'filtered_count': len(vulnerabilities) if len(vulnerabilities) != len(all_vulnerabilities) else None,
        }
        
        return render(request, 'xScout/vulnerability_viewer.html', context)
        
    except Exception as e:
        logger.error(f"Error loading vulnerability viewer: {str(e)}")
        messages.error(request, f"Error loading vulnerability data: {str(e)}")
        return redirect('xquire:firmware_detail', pk=firmware_id)

def firmware_comparison(request):
    """Compare security analysis between multiple firmwares"""
    if request.method == 'POST':
        # Get selected firmware IDs
        firmware_ids = request.POST.getlist('firmware_ids')
        
        if len(firmware_ids) < 2:
            messages.error(request, "Please select at least 2 firmwares to compare")
            return redirect('xscout:firmware_comparison')
        
        try:
            # Convert to integers
            firmware_ids = [int(fw_id) for fw_id in firmware_ids]
            
            # Get comparison data
            security_service = SecurityAnalysisService()
            comparison_data = security_service.compare_firmwares(firmware_ids)
            
            if 'error' in comparison_data:
                messages.error(request, comparison_data['error'])
                return redirect('xscout:firmware_comparison')
            
            context = {
                'comparison_data': comparison_data,
                'firmware_ids': firmware_ids,
            }
            
            return render(request, 'xScout/firmware_comparison_results.html', context)
            
        except ValueError:
            messages.error(request, "Invalid firmware IDs")
            return redirect('xscout:firmware_comparison')
        except Exception as e:
            logger.error(f"Error comparing firmwares: {str(e)}")
            messages.error(request, f"Error comparing firmwares: {str(e)}")
            return redirect('xscout:firmware_comparison')
    
    # GET request - show firmware selection
    try:
        security_service = SecurityAnalysisService()
        security_analyses = security_service.list_all_security_analyses(limit=50)
        
        # Get firmware objects
        firmware_list = []
        for analysis in security_analyses:
            try:
                firmware = Firmware.objects.get(pk=analysis.firmware_id)
                firmware_list.append({
                    'firmware': firmware,
                    'analysis': analysis,
                })
            except Firmware.DoesNotExist:
                continue
        
        context = {
            'firmware_list': firmware_list,
        }
        
        return render(request, 'xScout/firmware_comparison.html', context)
        
    except Exception as e:
        logger.error(f"Error loading firmware comparison page: {str(e)}")
        messages.error(request, f"Error loading firmware list: {str(e)}")
        return render(request, 'xScout/firmware_comparison.html', {'firmware_list': []})


# ===================================== xScout Orchestration ==============================================

# API Views
@csrf_exempt
def run_complete_workflow(request):
    """API endpoint to run complete workflow: extract -> analyze -> security"""
    if request.method != 'POST':
        return JsonResponse({
            'success': False,
            'message': "Only POST method is allowed"
        }, status=405)
    
    # Get parameters
    firmware_id = request.POST.get('firmware_id')
    workflow_type = request.POST.get('workflow_type', 'complete')  # complete, binary_only, extract_only, extract_analyze, analyze_only, security_only
    
    if not firmware_id:
        return JsonResponse({
            'success': False,
            'message': "Firmware ID is required"
        }, status=400)
    
    try:
        # Get firmware
        firmware = Firmware.objects.get(pk=firmware_id)
        
        # Check if firmware file exists
        if not os.path.exists(firmware.file.path):
            return JsonResponse({
                'success': False,
                'message': f"Firmware file not found: {firmware.file.path}"
            }, status=404)
        
        results = {'firmware_info': f"{firmware.model.manufacturer.name} {firmware.model.model_number} - {firmware.version}"}
        
        # Step 1: Firmware Binary Analysis (if requested)
        if workflow_type in ['complete', 'binary_only']:
            analysis_service = FirmwareAnalysisService()
            analysis_id = analysis_service.analyze_firmware(int(firmware_id))
            if analysis_id:
                results['fw_binary_analysis'] = {'success': True, 'analysis_id': analysis_id}
            else:
                results['fw_binary_analysis'] = {'success': False, 'error': 'Failed to start Firmware binary analysis'}
                if workflow_type == 'binary_only':
                    return JsonResponse({'success': False, 'results': results})
        
        # Step 2: Extraction (if requested)
        if workflow_type in ['complete', 'extract_only', 'extract_analyze', 'extract_security']:
            extraction_service = FirmwareExtractionService()
            success, message = extraction_service.extract_firmware(int(firmware_id))
            if success:
                results['extraction'] = {'success': True, 'message': message}
            else:
                results['extraction'] = {'success': False, 'error': message}
                return JsonResponse({'success': False, 'results': results})
        
        # Step 3: Components Analysis (if requested)
        if workflow_type in ['complete', 'analyze_only', 'extract_analyze', 'analyze_security']:
            components_analysis_service = ComponentsAnalysisService()
            
            # Check if extraction is completed using xfs utilities
            extraction_status = get_extraction_status(firmware_id)
            if not extraction_status['extraction_completed']:
                if not extraction_status['is_extracted']:
                    error_msg = 'No extraction found - extract firmware first'
                else:
                    error_msg = 'Extraction not yet completed - wait for extraction to finish'
                results['components_analysis'] = {'success': False, 'error': error_msg}
                return JsonResponse({'success': False, 'results': results})
            
            analysis_results = components_analysis_service.analyze_extracted_firmware(int(firmware_id))
            if analysis_results:
                results['components_analysis'] = {'success': True, 'results': 'Analysis completed'}
            else:
                results['components_analysis'] = {'success': False, 'error': 'Failed to analyze extracted firmware'}
                if workflow_type in ['analyze_only', 'extract_analyze']:
                    return JsonResponse({'success': False, 'results': results})
        
        # Step 4: Security Analysis (if requested)
        if workflow_type in ['complete', 'security_only', 'extract_security', 'analyze_security', 'extract_analyze']:
            components_analysis_service = ComponentsAnalysisService()
            security_results = components_analysis_service.run_full_security_analysis(int(firmware_id))
            
            if security_results and security_results.get('success'):
                sbom_results = security_results.get('sbom_results', {})
                vuln_results = security_results.get('vulnerability_results', {})
                vuln_summary = vuln_results.get('summary', {})
                
                results['security_analysis'] = {
                    'success': True,
                    'sbom_packages': sbom_results.get('total_packages', 0),
                    'total_vulnerabilities': vuln_summary.get('total_vulnerabilities', 0),
                    'critical_count': vuln_summary.get('severity_counts', {}).get('critical', 0),
                    'high_count': vuln_summary.get('severity_counts', {}).get('high', 0)
                }
                
                # Store in MongoDB if successful
                security_service = SecurityAnalysisService()
                doc_id = security_service.process_and_store_security_data(int(firmware_id))
                if doc_id:
                    results['security_analysis']['mongodb_doc_id'] = doc_id
                    
            else:
                results['security_analysis'] = {
                    'success': False, 
                    'error': security_results.get('error', 'Failed to run security analysis')
                }
                if workflow_type in ['security_only', 'extract_security', 'analyze_security']:
                    return JsonResponse({'success': False, 'results': results})
        
        return JsonResponse({
            'success': True,
            'message': f"Workflow '{workflow_type}' completed successfully",
            'results': results
        })
        
    except Firmware.DoesNotExist:
        return JsonResponse({
            'success': False,
            'message': f"Firmware with ID {firmware_id} not found"
        }, status=404)
    except Exception as e:
        logger.exception("Error running complete workflow")
        return JsonResponse({
            'success': False,
            'message': f"Error: {str(e)}"
        }, status=500)

@csrf_exempt
def api_security_summary(request, firmware_id):
    """API endpoint for security summary data"""
    try:
        security_service = SecurityAnalysisService()
        security_analysis = security_service.get_security_analysis(firmware_id)
        
        if not security_analysis:
            return JsonResponse({'error': 'Security analysis not found'}, status=404)
        
        summary_data = {
            'firmware_id': firmware_id,
            'risk_score': security_analysis.risk_score,
            'total_packages': security_analysis.get_total_packages(),
            'total_vulnerabilities': security_analysis.get_total_vulnerabilities(),
            'critical_vulnerabilities': security_analysis.get_critical_vulnerabilities(),
            'high_vulnerabilities': security_analysis.get_high_vulnerabilities(),
            'severity_counts': security_analysis.vulnerability_data.get('severity_counts', {}),
            'analysis_date': security_analysis.analysis_date.isoformat() if security_analysis.analysis_date else None,
        }
        
        return JsonResponse(summary_data)
        
    except Exception as e:
        logger.error(f"Error getting security summary API: {str(e)}")
        return JsonResponse({'error': str(e)}, status=500)

@csrf_exempt  
def api_vulnerability_search(request):
    """API endpoint for searching vulnerabilities by CVE"""
    try:
        cve_id = request.GET.get('cve_id', '')
        
        if not cve_id:
            return JsonResponse({'error': 'CVE ID is required'}, status=400)
        
        security_service = SecurityAnalysisService()
        affected_firmwares = security_service.find_by_cve(cve_id)
        
        results = []
        for analysis in affected_firmwares:
            try:
                firmware = Firmware.objects.get(pk=analysis.firmware_id)
                results.append({
                    'firmware_id': analysis.firmware_id,
                    'firmware_info': analysis.firmware_info,
                    'risk_score': analysis.risk_score,
                    'total_vulnerabilities': analysis.get_total_vulnerabilities(),
                })
            except Firmware.DoesNotExist:
                continue
        
        return JsonResponse({
            'cve_id': cve_id,
            'affected_firmwares': results,
            'count': len(results)
        })
        
    except Exception as e:
        logger.error(f"Error searching vulnerabilities API: {str(e)}")
        return JsonResponse({'error': str(e)}, status=500)

def firmware_analysis(request, firmware_id):
    """Unified firmware analysis page showing overview of all phases"""
    firmware = get_object_or_404(Firmware, pk=firmware_id)
    
    try:
        # Initialize services
        analysis_service = FirmwareAnalysisService()
        extraction_service = FirmwareExtractionService()
        components_analysis_service = ComponentsAnalysisService()
        security_service = SecurityAnalysisService()
        
        # Get firmware file info
        fw_name = os.path.splitext(os.path.basename(firmware.file.name))[0]
        fw_dir = os.path.dirname(firmware.file.path)
        
        # Phase 1: Firmware Binary Analysis Status
        fw_binary_analysis = analysis_service.get_latest_analysis_for_firmware(firmware_id)
        phase1_status = {
            'completed': bool(fw_binary_analysis and fw_binary_analysis.status == 'completed'),
            'running': bool(fw_binary_analysis and fw_binary_analysis.status not in ['completed', 'failed']),
            'failed': bool(fw_binary_analysis and fw_binary_analysis.status == 'failed'),
            'analysis': fw_binary_analysis,
            'progress': fw_binary_analysis.progress if fw_binary_analysis else 0
        }
        
                # Phase 2: Extraction Status
        #check if extraction is complete
        #check if linux rootfs was found
        extraction_dir = os.path.join(fw_dir, f"{fw_name}_extract")
        artifacts_dir = os.path.join(fw_dir, "artifacts")
        
        # Get extraction status using utility function
        extraction_status = get_extraction_status(firmware_id)
        
        # Extract values for compatibility
        is_extracted = extraction_status['is_extracted']
        extraction_progress = extraction_status['extraction_progress']
        is_running = extraction_status['is_running']
        rootfs_found = extraction_status['rootfs_found']
        rootfs_paths = [extraction_status['rootfs_path']] if extraction_status['rootfs_path'] else []
        
        phase2_status = {
            'completed': extraction_status['extraction_completed'],
            'partial': is_extracted and not extraction_status['extraction_completed'] and not is_running,
            'running': is_running,
            'not_started': not is_extracted,
            'extraction_dir': extraction_status['extraction_dir'],
            'rootfs_path': extraction_status['rootfs_path'],
            'progress': extraction_progress
        }
        
        
        # Phase 3: Component Analysis Status
        analysis_results = None
        if rootfs_found:
            try:
                analysis_results = components_analysis_service.get_analysis_results(firmware_id)
            except Exception as e:
                logger.warning(f"Error getting analysis results for firmware {firmware_id}: {e}")
                analysis_results = None
        
        phase3_status = {
            'completed': bool(analysis_results is not None),
            'not_started': bool(analysis_results is None),
            'results': analysis_results,
            'requires_extraction': bool(not rootfs_found)
        }
        
        # Phase 4: Security Analysis Status
        try:
            security_analysis = security_service.get_security_analysis(firmware_id)
        except Exception as e:
            logger.warning(f"Error getting security analysis for firmware {firmware_id}: {e}")
            security_analysis = None
            
        try:
            sbom_path = os.path.join(artifacts_dir, "sbom.json")
            vuln_path = os.path.join(artifacts_dir, "vulnerabilities.json")
            has_sbom = os.path.exists(sbom_path)
            has_vulnerabilities = os.path.exists(vuln_path)
        except (OSError, PermissionError):
            has_sbom = False
            has_vulnerabilities = False
        
        phase4_status = {
            'completed': bool(security_analysis is not None),
            'partial': bool(has_sbom or has_vulnerabilities),
            'not_started': bool(security_analysis is None and not has_sbom),
            'analysis': security_analysis,
            'has_sbom': bool(has_sbom),
            'has_vulnerabilities': bool(has_vulnerabilities),
            'requires_extraction': bool(not rootfs_found)
        }
        
        # Overall progress calculation - ensure all values are boolean
        phases_completed = sum([
            phase1_status['completed'],
            phase2_status['completed'], 
            phase3_status['completed'],
            phase4_status['completed']
        ])
        overall_progress = (phases_completed / 4) * 100
        
        # Quick stats for overview cards
        quick_stats = {
            'file_size': firmware.file_size if hasattr(firmware, 'file_size') else None,
            'upload_date': firmware.upload_date,
            'overall_progress': overall_progress,
            'phases_completed': phases_completed,
            'total_phases': 4
        }
        
        # Add security stats if available
        if security_analysis:
            quick_stats.update({
                'total_packages': security_analysis.get_total_packages(),
                'total_vulnerabilities': security_analysis.get_total_vulnerabilities(),
                'critical_vulnerabilities': security_analysis.get_critical_vulnerabilities(),
                'risk_score': security_analysis.risk_score
            })
        
        context = {
            'firmware': firmware,
            'phase1_status': phase1_status,
            'phase2_status': phase2_status,
            'phase3_status': phase3_status,
            'phase4_status': phase4_status,
            'quick_stats': quick_stats,
            'artifacts_dir': artifacts_dir
        }
        
        return render(request, 'xScout/firmware_analysis.html', context)
        
    except Exception as e:
        logger.exception(f"Error loading firmware analysis for {firmware_id}")
        messages.error(request, f"Error loading firmware analysis: {str(e)}")
        return redirect('xquire:firmware_detail', pk=firmware_id)
