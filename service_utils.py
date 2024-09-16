# service_utils.py

import socket

class ServiceUtils:

    @staticmethod
    def grab_banner(ip: str, port: int) -> str:
        """
        The `grab_banner` function attempts to retrieve a banner from a specified IP
        address and port, handling different ports like 80 and 443 with specific
        requests.
        
        :param ip: The `ip` parameter in the `grab_banner` method is a string that
        represents the IP address of the target server or device from which you want to
        grab the banner
        :type ip: str
        :param port: The `port` parameter in the `grab_banner` method is an integer that
        represents the port number on which the socket connection will be established to
        grab the banner from the specified IP address. Ports are used to differentiate
        between different services running on the same IP address. Common ports include
        80 for HTTP
        :type port: int
        :return: The `grab_banner` method returns a string. If a banner is successfully
        received from the specified IP address and port, the banner content is returned.
        If no banner is received, it returns "No banner received". If an exception
        occurs during the process, it returns an error message indicating the specific
        port where the error occurred.
        """
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(2)
                sock.connect((ip, port))
                if port == 80 or port == 443:
                    request = "HEAD / HTTP/1.1\r\nHost: {}\r\n\r\n".format(ip)
                    sock.send(request.encode())
                banner = sock.recv(1024).decode(errors='ignore').strip()
                if banner:
                    return banner
                else:
                    return "No banner received"
        except Exception as e:
            return f"Error on port {port}: {str(e)}"
