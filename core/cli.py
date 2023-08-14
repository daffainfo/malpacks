from colorama import Fore, Style

def banner():
    banner = Fore.BLUE + """
 #    #    ##    #       #####     ##     ####   #    #   ####  
 ##  ##   #  #   #       #    #   #  #   #    #  #   #   #      
 # ## #  #    #  #       #    #  #    #  #       ####     ####  
 #    #  ######  #       #####   ######  #       #  #         # 
 #    #  #    #  #       #       #    #  #    #  #   #   #    # 
 #    #  #    #  ######  #       #    #   ####   #    #   ####  

Version: 1.0.0
Author: daffainfo
"""

    print(banner + Style.RESET_ALL)