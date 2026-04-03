"""
ANSI to HTML conversion utilities
"""
import re
import html


class AnsiToHtmlConverter:
    """
    Converts ANSI escape sequences to HTML with styling
    """
    
    # ANSI color codes mapping to CSS classes
    ANSI_COLOR_MAP = {
        # Foreground colors
        '30': 'ansi-fg-black',
        '31': 'ansi-fg-red',
        '32': 'ansi-fg-green',
        '33': 'ansi-fg-yellow',
        '34': 'ansi-fg-blue',
        '35': 'ansi-fg-magenta',
        '36': 'ansi-fg-cyan',
        '37': 'ansi-fg-white',
        '90': 'ansi-fg-bright-black',
        '91': 'ansi-fg-bright-red',
        '92': 'ansi-fg-bright-green',
        '93': 'ansi-fg-bright-yellow',
        '94': 'ansi-fg-bright-blue',
        '95': 'ansi-fg-bright-magenta',
        '96': 'ansi-fg-bright-cyan',
        '97': 'ansi-fg-bright-white',
        
        # Background colors
        '40': 'ansi-bg-black',
        '41': 'ansi-bg-red',
        '42': 'ansi-bg-green',
        '43': 'ansi-bg-yellow',
        '44': 'ansi-bg-blue',
        '45': 'ansi-bg-magenta',
        '46': 'ansi-bg-cyan',
        '47': 'ansi-bg-white',
        '100': 'ansi-bg-bright-black',
        '101': 'ansi-bg-bright-red',
        '102': 'ansi-bg-bright-green',
        '103': 'ansi-bg-bright-yellow',
        '104': 'ansi-bg-bright-blue',
        '105': 'ansi-bg-bright-magenta',
        '106': 'ansi-bg-bright-cyan',
        '107': 'ansi-bg-bright-white',
    }
    
    # Text formatting codes
    ANSI_FORMAT_MAP = {
        '1': 'ansi-bold',
        '2': 'ansi-dim',
        '3': 'ansi-italic',
        '4': 'ansi-underline',
        '5': 'ansi-blink',
        '7': 'ansi-reverse',
        '8': 'ansi-hidden',
        '9': 'ansi-strikethrough',
    }
    
    @classmethod
    def get_css_styles(cls):
        """
        Return CSS styles for ANSI color classes
        """
        return """
        <style>
        .ansi-log {
            background: #1e1e1e;
            color: #d4d4d4;
            font-family: 'Monaco', 'Menlo', 'Ubuntu Mono', monospace;
            font-size: 13px;
            line-height: 1.4;
            padding: 16px;
            border-radius: 8px;
            overflow-x: auto;
            white-space: pre-wrap;
            word-wrap: break-word;
        }
        
        /* Foreground colors */
        .ansi-fg-black { color: #000000; }
        .ansi-fg-red { color: #cd3131; }
        .ansi-fg-green { color: #0dbc79; }
        .ansi-fg-yellow { color: #e5e510; }
        .ansi-fg-blue { color: #2472c8; }
        .ansi-fg-magenta { color: #bc3fbc; }
        .ansi-fg-cyan { color: #11a8cd; }
        .ansi-fg-white { color: #e5e5e5; }
        .ansi-fg-bright-black { color: #666666; }
        .ansi-fg-bright-red { color: #f14c4c; }
        .ansi-fg-bright-green { color: #23d18b; }
        .ansi-fg-bright-yellow { color: #f5f543; }
        .ansi-fg-bright-blue { color: #3b8eea; }
        .ansi-fg-bright-magenta { color: #d670d6; }
        .ansi-fg-bright-cyan { color: #29b8db; }
        .ansi-fg-bright-white { color: #e5e5e5; }
        
        /* Background colors */
        .ansi-bg-black { background-color: #000000; }
        .ansi-bg-red { background-color: #cd3131; }
        .ansi-bg-green { background-color: #0dbc79; }
        .ansi-bg-yellow { background-color: #e5e510; }
        .ansi-bg-blue { background-color: #2472c8; }
        .ansi-bg-magenta { background-color: #bc3fbc; }
        .ansi-bg-cyan { background-color: #11a8cd; }
        .ansi-bg-white { background-color: #e5e5e5; }
        .ansi-bg-bright-black { background-color: #666666; }
        .ansi-bg-bright-red { background-color: #f14c4c; }
        .ansi-bg-bright-green { background-color: #23d18b; }
        .ansi-bg-bright-yellow { background-color: #f5f543; }
        .ansi-bg-bright-blue { background-color: #3b8eea; }
        .ansi-bg-bright-magenta { background-color: #d670d6; }
        .ansi-bg-bright-cyan { background-color: #29b8db; }
        .ansi-bg-bright-white { background-color: #e5e5e5; }
        
        /* Text formatting */
        .ansi-bold { font-weight: bold; }
        .ansi-dim { opacity: 0.6; }
        .ansi-italic { font-style: italic; }
        .ansi-underline { text-decoration: underline; }
        .ansi-blink { animation: blink 1s linear infinite; }
        .ansi-reverse { 
            background-color: #d4d4d4; 
            color: #1e1e1e; 
        }
        .ansi-hidden { opacity: 0; }
        .ansi-strikethrough { text-decoration: line-through; }
        
        @keyframes blink {
            0%, 50% { opacity: 1; }
            51%, 100% { opacity: 0; }
        }
        </style>
        """
    
    @classmethod
    def convert(cls, text):
        """
        Convert ANSI escape sequences to HTML
        
        Args:
            text: Text containing ANSI escape sequences
            
        Returns:
            HTML string with ANSI codes converted to styled spans
        """
        if not text:
            return ""
        
        # Escape HTML characters first
        html_text = html.escape(text)
        
        # ANSI escape sequence pattern
        ansi_pattern = re.compile(r'\x1b\[([\d;]*)(m)')
        
        result = []
        last_end = 0
        current_classes = []
        
        for match in ansi_pattern.finditer(html_text):
            start, end = match.span()
            
            # Add text before this escape sequence
            if start > last_end:
                text_chunk = html_text[last_end:start]
                if current_classes:
                    result.append(f'<span class="{" ".join(current_classes)}">{text_chunk}</span>')
                else:
                    result.append(text_chunk)
            
            # Process the escape sequence
            codes = match.group(1).split(';') if match.group(1) else ['0']
            
            for code in codes:
                if not code:
                    continue
                    
                if code == '0':
                    # Reset all formatting
                    if current_classes:
                        # Close previous span if there are classes
                        current_classes = []
                elif code in cls.ANSI_COLOR_MAP:
                    # Add color class
                    color_class = cls.ANSI_COLOR_MAP[code]
                    # Remove any existing foreground/background class of same type
                    if color_class.startswith('ansi-fg-'):
                        current_classes = [c for c in current_classes if not c.startswith('ansi-fg-')]
                    elif color_class.startswith('ansi-bg-'):
                        current_classes = [c for c in current_classes if not c.startswith('ansi-bg-')]
                    current_classes.append(color_class)
                elif code in cls.ANSI_FORMAT_MAP:
                    # Add formatting class
                    format_class = cls.ANSI_FORMAT_MAP[code]
                    if format_class not in current_classes:
                        current_classes.append(format_class)
            
            last_end = end
        
        # Add remaining text
        if last_end < len(html_text):
            text_chunk = html_text[last_end:]
            if current_classes:
                result.append(f'<span class="{" ".join(current_classes)}">{text_chunk}</span>')
            else:
                result.append(text_chunk)
        
        return ''.join(result)
    
    @classmethod
    def convert_to_html_document(cls, text, title="Log Output"):
        """
        Convert ANSI text to a complete HTML document with embedded CSS
        
        Args:
            text: Text containing ANSI escape sequences
            title: Title for the HTML document
            
        Returns:
            Complete HTML document string
        """
        converted_content = cls.convert(text)
        css_styles = cls.get_css_styles()
        
        return f"""
        {css_styles}
        <div class="ansi-log">{converted_content}</div>
        """


def convert_ansi_to_html(text):
    """
    Convenience function to convert ANSI text to HTML
    
    Args:
        text: Text containing ANSI escape sequences
        
    Returns:
        HTML string with ANSI codes converted to styled spans
    """
    return AnsiToHtmlConverter.convert(text)


def get_ansi_css():
    """
    Get CSS styles for ANSI display
    
    Returns:
        CSS string for ANSI styling
    """
    return AnsiToHtmlConverter.get_css_styles()
