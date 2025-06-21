# -*- coding: utf-8 -*-
import os

# ANSI color functions
def color_success(text):
    return f"\033[92m{text}\033[0m"  # Green

def color_status(text):
    return f"\033[94m{text}\033[0m"  # Blue

def color_red(text):
    return f"\033[91m{text}\033[0m"  # Red

class SomeFrameworkUI:
    def __init__(self):
        # Simulated framework modules
        self.frmwk = type('obj', (object,), {
            'modules': {
                'exploit/windows/smb/ms17_010_eternalblue': type('obj', (object,), {'description': 'SMB EternalBlue RCE'}),
                'auxiliary/scanner/http/f5_bigip_tmui_version': type('obj', (object,), {'description': 'F5 BIG-IP TMUI Version Detection'}),
                'exploit/linux/web/apache_struts_rce': type('obj', (object,), {'description': 'Apache Struts Remote Code Execution'}),
                'post/windows/gather/enum_users': type('obj', (object,), {'description': 'Enumerate Windows Users'}),
                'auxiliary/scanner/http/tomcat_enum': type('obj', (object,), {'description': 'Tomcat Enumeration'})
            }
        })()

    def print_line(self, text):
        print(text)

    def do_search(self, key):
        """Search for a module"""
        findmodules = [
            module_name for module_name in self.frmwk.modules.keys()
            if key.lower() in module_name.lower()
        ]

        if not findmodules:
            self.print_line(color_success('No modules found.'))
            return

        self.print_line(os.linesep + color_success('Modules') +
                        os.linesep + '=======' + os.linesep)

        longest_name = 20  # Minimum width for 'Name' column

        # Calculate longest module name for alignment
        for module_name in findmodules:
            longest_name = max(longest_name, len(module_name))

        # Header
        self.print_line(color_status(f"  {'Name':<{longest_name}} Description"))
        self.print_line(f"  {'-' * longest_name} -----------")

        # Print each module
        for module_name in sorted(findmodules):
            module_obj = self.frmwk.modules[module_name]
            colored_name = ""
            start_index = 0
            # Highlight all instances of the keyword
            lower_name = module_name.lower()
            lower_key = key.lower()
            while True:
                idx = lower_name.find(lower_key, start_index)
                if idx == -1:
                    break
                colored_name += module_name[start_index:idx]
                colored_name += color_red(module_name[idx:idx + len(key)])
                start_index = idx + len(key)
            colored_name += module_name[start_index:]

            # Pad to align with longest name
            padding = ' ' * (longest_name - len(module_name))
            self.print_line(f"  {colored_name}{padding} {module_obj.description}")

        self.print_line('')

# Example usage
if __name__ == "__main__":
    ui = SomeFrameworkUI()
    print("\n--- 搜索 'smb' ---")
    ui.do_search('smb')
    print("\n--- 搜索 'f5' ---")
    ui.do_search('f5')
    print("\n--- 搜索 'linux' ---")
    ui.do_search('linux')
    print("\n--- 搜索 'nonexistent' ---")
    ui.do_search('nonexistent')