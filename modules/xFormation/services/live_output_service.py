"""
Live Output Service for xFormation

Handles real-time output streaming from penguin instances
"""

import threading
import queue
import logging
import time
import re
from collections import defaultdict
from typing import Dict, List, Callable

try:
    from ansi2html import Ansi2HTMLConverter
    ANSI2HTML_AVAILABLE = True
except ImportError:
    ANSI2HTML_AVAILABLE = False

logger = logging.getLogger(__name__)

class LiveOutputService:
    """Service for handling live output from emulation instances"""
    
    # Class-level storage for output buffers and subscribers
    _output_buffers: Dict[int, List[str]] = defaultdict(list)
    _subscribers: Dict[int, List[Callable]] = defaultdict(list)
    _buffer_locks: Dict[int, threading.Lock] = defaultdict(threading.Lock)
    
    # Configuration
    MAX_BUFFER_SIZE = 1000  # Maximum lines to keep in buffer
    
    # Initialize ansi2html converter
    _ansi_converter = Ansi2HTMLConverter(dark_bg=True, scheme='xterm') if ANSI2HTML_AVAILABLE else None
    
    @classmethod
    def _process_ansi_line(cls, text: str) -> str:
        """
        Process ANSI escape codes in text - convert to HTML or strip them
        
        Args:
            text: Text that may contain ANSI codes
            
        Returns:
            Text with ANSI codes processed (HTML or stripped)
        """
        if ANSI2HTML_AVAILABLE and cls._ansi_converter:
            # Convert ANSI codes to HTML
            html = cls._ansi_converter.convert(text, full=False)
            return html
        else:
            # Fallback: strip ANSI codes
            ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
            return ansi_escape.sub('', text)
    
    @classmethod
    def start_monitoring(cls, instance, output_stream):
        """
        Start monitoring output from a penguin instance
        
        Args:
            instance: EmulationInstance object
            output_stream: Stream to read output from
        """
        def monitor_worker():
            instance_id = instance.id
            logger.info(f"Started output monitoring for instance {instance_id}")
            
            try:
                for line in iter(output_stream.readline, ''):
                    if not line:
                        break
                    
                    line = line.strip()
                    if line:
                        # Process ANSI escape codes (convert to HTML or strip)
                        processed_line = cls._process_ansi_line(line)
                        # Add timestamp
                        timestamped_line = f"[{time.strftime('%H:%M:%S')}] {processed_line}"
                        
                        # Add to buffer
                        with cls._buffer_locks[instance_id]:
                            cls._output_buffers[instance_id].append(timestamped_line)
                            
                            # Trim buffer if too large
                            if len(cls._output_buffers[instance_id]) > cls.MAX_BUFFER_SIZE:
                                cls._output_buffers[instance_id] = cls._output_buffers[instance_id][-cls.MAX_BUFFER_SIZE:]
                        
                        # Notify subscribers
                        cls._notify_subscribers(instance_id, timestamped_line)
                
                logger.info(f"Output monitoring ended for instance {instance_id}")
                
            except Exception as e:
                logger.error(f"Error monitoring output for instance {instance_id}: {e}")
        
        thread = threading.Thread(target=monitor_worker, daemon=True)
        thread.start()
    
    @classmethod
    def get_output_buffer(cls, instance_id: int, last_n_lines: int = None) -> List[str]:
        """
        Get the output buffer for an instance
        
        Args:
            instance_id: ID of the EmulationInstance
            last_n_lines: Number of recent lines to return (None for all)
            
        Returns:
            List of output lines
        """
        with cls._buffer_locks[instance_id]:
            buffer = cls._output_buffers[instance_id]
            if last_n_lines:
                return buffer[-last_n_lines:]
            return buffer.copy()
    
    @classmethod
    def subscribe_to_output(cls, instance_id: int, callback: Callable[[str], None]):
        """
        Subscribe to live output updates for an instance
        
        Args:
            instance_id: ID of the EmulationInstance
            callback: Function to call with each new line
        """
        cls._subscribers[instance_id].append(callback)
        logger.info(f"Added subscriber for instance {instance_id}")
    
    @classmethod
    def unsubscribe_from_output(cls, instance_id: int, callback: Callable[[str], None]):
        """
        Unsubscribe from output updates for an instance
        
        Args:
            instance_id: ID of the EmulationInstance
            callback: Function to remove from subscribers
        """
        if callback in cls._subscribers[instance_id]:
            cls._subscribers[instance_id].remove(callback)
            logger.info(f"Removed subscriber for instance {instance_id}")
    
    @classmethod
    def _notify_subscribers(cls, instance_id: int, line: str):
        """
        Notify all subscribers of a new output line
        
        Args:
            instance_id: ID of the EmulationInstance
            line: New output line
        """
        for callback in cls._subscribers[instance_id]:
            try:
                callback(line)
            except Exception as e:
                logger.error(f"Error notifying subscriber for instance {instance_id}: {e}")
    
    @classmethod
    def clear_output_buffer(cls, instance_id: int):
        """
        Clear the output buffer for an instance
        
        Args:
            instance_id: ID of the EmulationInstance
        """
        with cls._buffer_locks[instance_id]:
            cls._output_buffers[instance_id].clear()
        logger.info(f"Cleared output buffer for instance {instance_id}")
    
    @classmethod
    def cleanup_instance_data(cls, instance_id: int):
        """
        Clean up all data for an instance
        
        Args:
            instance_id: ID of the EmulationInstance
        """
        with cls._buffer_locks[instance_id]:
            cls._output_buffers.pop(instance_id, None)
            cls._subscribers.pop(instance_id, None)
            cls._buffer_locks.pop(instance_id, None)
        
        logger.info(f"Cleaned up data for instance {instance_id}")
    
    @classmethod
    def get_active_instances(cls) -> List[int]:
        """
        Get list of instance IDs that have active output monitoring
        
        Returns:
            List of instance IDs
        """
        return list(cls._output_buffers.keys())

class WebSocketOutputHandler:
    """Handler for WebSocket-based live output streaming"""
    
    def __init__(self, instance_id: int):
        self.instance_id = instance_id
        self.websocket = None
        self.is_connected = False
    
    def connect(self, websocket):
        """
        Connect a WebSocket for live output
        
        Args:
            websocket: WebSocket connection
        """
        self.websocket = websocket
        self.is_connected = True
        
        # Subscribe to output updates
        LiveOutputService.subscribe_to_output(self.instance_id, self._send_to_websocket)
        
        # Send existing buffer
        buffer = LiveOutputService.get_output_buffer(self.instance_id, last_n_lines=100)
        for line in buffer:
            self._send_to_websocket(line)
        
        logger.info(f"WebSocket connected for instance {self.instance_id}")
    
    def disconnect(self):
        """
        Disconnect the WebSocket
        """
        if self.is_connected:
            LiveOutputService.unsubscribe_from_output(self.instance_id, self._send_to_websocket)
            self.is_connected = False
            self.websocket = None
            logger.info(f"WebSocket disconnected for instance {self.instance_id}")
    
    def _send_to_websocket(self, line: str):
        """
        Send a line to the WebSocket
        
        Args:
            line: Output line to send
        """
        if self.is_connected and self.websocket:
            try:
                import json
                message = json.dumps({
                    'type': 'output',
                    'instance_id': self.instance_id,
                    'line': line,
                    'timestamp': time.time()
                })
                self.websocket.send(message)
            except Exception as e:
                logger.error(f"Error sending to WebSocket for instance {self.instance_id}: {e}")
                self.disconnect()


