# traceroute_utils.py

import platform
import subprocess

class TracerouteUtils:
    @staticmethod
    def traceroute(fqdn: str, timeout: int = 10) -> str:
        try:
            if platform.system().lower() == "windows":
                return "Traceroute is not available on Windows. Please use an alternative method."
            
            result = subprocess.run(
                ["traceroute", fqdn],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=timeout,
            )
            
            if result.returncode == 0:
                return result.stdout
            else:
                return f"Error: {result.stderr}"
        except subprocess.TimeoutExpired:
            return f"Traceroute timed out after {timeout} seconds."
        except FileNotFoundError:
            return "Traceroute command not found. Please install traceroute or use another method."
        except Exception as e:
            return str(e)
