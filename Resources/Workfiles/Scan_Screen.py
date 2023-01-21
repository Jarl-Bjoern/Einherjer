#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Rainer Christian Bjoern Herold

# Libraries
from Resources.Header_Files.Variables import *

class Web:
    def Driver_Specification(option):
        try:
            if (osname == 'nt'): driver = webdriver.Chrome(service=Service(join(dirname(realpath(__file__)), 'Resources/Webdriver/chromedriver.exe')), options=option)
            else: driver = webdriver.Chrome(service=Service(join(dirname(realpath(__file__)), 'Resources/Webdriver/chromedriver')), options=option)
        except WebDriverException:
            Chromium_Check = getoutput("apt-cache policy chromium").splitlines()[1][1:].split(":")[1][1:])
            if ('none' in Chromium_Check): Logs.Error_Message("\nIt looks like that you do not have Chromium installed.\n\nPlease use apt install -y chromium or set up the location of your custom chromium path as a argument.\n")
            else: Logs.Error_Message("\nChromium: {Chromium_Check}\n\nIt looks like that you do not have Chromedriver installed.\n\nPlease go to https://chromedriver.chromium.org/downloads and download the correct chromedriver and paste it into the Resources folder.\n")
        return driver

    def Configurate_Driver(options, driver = None):
        try: driver = Web.Driver_Specification(options)
        except (ConnectionError): pass
        except (MaxRetryError, ProxyError, ProxySchemeUnknown): Logs.Error_Message("\n\nThere is a error in your proxy configuration or the proxy server is blocking your connection.\n\n")
        except (gaierror, NewConnectionError): Logs.Error_Message("\n\nIt was not possible to connect to the Server.\n\n")
        except SessionNotCreatedException as e:
            if (osname != 'nt'):
                print (f'Chromium: {getoutput("apt-cache policy chromium").splitlines()[1][1:].split(":")[1][1:]})')
                for _ in str(e).splitlines():
                    if ("chrome=" in _):
                        print(f'Webdriver: {_.split("chrome=")[1][:-1]}')
                if ('xfce' in getoutput('ls /usr/bin/*session') or 'gnome' in getoutput('ls /usr/bin/*session')):
                    sleep(3.5), webbrowser_open("https://chromedriver.chromium.org/downloads")
            Logs.Error_Message("\nIt looks like you do not have the correct Chromedriver version installed.\n\nPlease go to https://chromedriver.chromium.org/downloads and download the correct chromedriver and paste it into the Resources folder.\n")
        except WebDriverException:
        except WebDriverException:
            Chromium_Check = getoutput("apt-cache policy chromium").splitlines()[1][1:].split(":")[1][1:])
            if ('none' in Chromium_Check): Logs.Error_Message("\nIt looks like that you do not have Chromium installed.\n\nPlease use apt install -y chromium or set up the location of your custom chromium path as a argument.\n")
            else: Logs.Error_Message(f"\nChromium: {Chromium_Check}\n\nIt looks like that you do not have Chromedriver installed.\n\nPlease go to https://chromedriver.chromium.org/downloads and download the correct chromedriver and paste it into the Resources folder.\n")
        return driver

    def Screenshot_Filter(Path):
        for Pictures in listdir(Path):
            Picture = imread(join(Path, Pictures))
            for _ in listdir(Path):
                if (_ != Picture):
                    Duplicate = imread(join(Path, _))
                    Difference = subtract(Picture, Duplicate)
                    b,g,r = cvsplit(difference)

                    if (countNonZero(b) == 0 and countNonZero(g) == 0 and countNonZero(r) == 0):
                        pass

def Take_Screenshot(driver, url, location, switch_connection):
    if (switch_connection == True):
        if (osname == 'nt'):
            Chrome_Path = ChromeDriverManager().install()
            driver = webdriver.Chrome(service=Service(Chrome_Path), options=options)
        else:
            driver = Web.Driver_Specification(options)
    else: driver = Web.Driver_Specification(options)
    driver.implicitly_wait(args.timeout), driver.set_window_size(1920,1080), driver.execute_script("document.body.style.zoom='250%'")

    Screen_Dir = join(location, 'Screenshots')
    try: makedirs(Screen_Dir)
    except FileExistsError: pass
    if ("://" in url): Screen_Name = url.split('://')[1]
    else: Screen_Name = url
    try:
        driver.get(url)
        driver.save_screenshot(join(Screen_Dir, f"{Date}_({Screen_Name}).png"))
    except MaxRetryError: Log_File(f'{strftime("%Y-%m-%d_%H:%M:%S")} - {url} - It was not possible to connect to the website to take screenshots\n')
    finally: driver.quit()

    for Picture in listdir(Screen_Dir):
        raw_image = imread(join(Screen_Dir, Picture))
        height = raw_image.shape[0]
        width = raw_image.shape[1]
        start_point, end_point = (0,0), (width, height)
        color = (0,0,0)
        thickness = 10
        img = rectangle(raw_image, start_point, end_point, color, thickness)
        imwrite(join(Screen_Dir, Picture), img)
