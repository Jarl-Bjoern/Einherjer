#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Rainer Christian Bjoern Herold

# Libraries
from ..Header_Files.Variables     import *
from ..Standard_Operations.Logs   import Logs
from ..Standard_Operations.Colors import Colors

class Web:
    def Driver_Specification(options, driver_path):
        return webdriver.Chrome(service=Service(driver_path), options=options)

    def Configurate_Driver(options, driver = None):
        try: driver = Web.Driver_Specification(options)
        except AttributeError as e:                             Logs.Error_Message(f"It was not possible to use the chromedriver. Please check that the used chromedriver is a executeable file or try a another one.\n")
        except ConnectionError:                                 pass
        except (MaxRetryError, ProxyError, ProxySchemeUnknown): Logs.Error_Message("\n\nThere is a error in your proxy configuration or the proxy server is blocking your connection.\n\n")
        except (gaierror, NewConnectionError):                  Logs.Error_Message("\n\nIt was not possible to connect to the Server.\n\n")
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
            Chromium_Check = getoutput("apt-cache policy chromium").splitlines()[1][1:].split(":")[1][1:]
            if ('none' in Chromium_Check): Logs.Error_Message("\nIt looks like that you do not have Chromium installed.\n\nPlease use apt install -y chromium or set up the location of your custom chromium path as a argument.\n")
            else:                          Logs.Error_Message(f"\nChromium: {Chromium_Check}\n\nIt looks like that you do not have Chromedriver installed.\n\nPlease go to https://chromedriver.chromium.org/downloads and download the correct chromedriver and paste it into the Resources folder.\n")
        return driver

    def Screenshot_Filter(Path, Location, Temp_Output_File = ""):
        for Picture in listdir(Path):
            Original_Picture = imread(join(Path, Picture))
            for _ in listdir(Path):
                if (_ != Picture):
                    try:
                        Duplicate  = imread(join(Path, _))
                        Difference = subtract(Original_Picture, Duplicate)
                        b,g,r      = cvsplit(Difference)

                        if (countNonZero(b) == 0 and countNonZero(g) == 0 and countNonZero(r) == 0):
                            remove(join(Path, _))
                            Temp_Output_File = join(Location, 'duplicates.txt')
                            with open(Temp_Output_File, 'a') as f:
                                f.write(f'{join(Path, Picture)} : {join(Path, _)}\n')
                    except (CVError, FileNotFoundError):
                        pass
        return Temp_Output_File

def Take_Screenshot(url, driver_options, driver_path, Screen_Dir, switch_internet_connection, screenshot_wait, webdriver_timeout, screenshot_frame_thickness, screen_frame_switch, Screen_Type):
    if (switch_internet_connection == True):
        if (osname == 'nt'):
            Chrome_Path = ChromeDriverManager().install()
            driver      = webdriver.Chrome(service=Service(Chrome_Path), options=driver_options)
        else:
            driver      = Web.Driver_Specification(driver_options, driver_path)
    else:   driver      = Web.Driver_Specification(driver_options, driver_path)
    driver.implicitly_wait(webdriver_timeout), driver.set_window_size(1920,1080), driver.execute_script("document.body.style.zoom='250%'")

    if ("://" in url): Screen_Name = url.split('://')[1]
    else:              Screen_Name = url
    try:
        if (':' in Screen_Name): Full_Screen_Name = join(Screen_Dir, f"{Date}_({Screen_Name.replace(':', '_')}).png")
        else:                    Full_Screen_Name = join(Screen_Dir, f"{Date}_({Screen_Name}).png")
        driver.get(url)
        sleep(screenshot_wait)
        driver.save_screenshot(Full_Screen_Name)
        if (exists(Full_Screen_Name)):
            Logs.Log_File(
                Colors.YELLOW+'-----------------------------------------------------------------------------------------------------------\n'
                +Colors.BLUE+'Screenshot-Check\n'
                +Colors.YELLOW+'-----------------------------------------------------------------------------------------------------------\n'
                +Colors.GREEN+f'{strftime("%Y-%m-%d %H:%M:%S")}'+Colors.RESET+f' - {url} - '+Colors.CYAN+'A screenshot was successfully taken from the website.\n'
                +Colors.BLUE+'-----------------------------------------------------------------------------------------------------------\n\n',
                Screen_Dir.replace('Screenshots', 'Logs')
            )
        else:
            Logs.Log_File(
                Colors.YELLOW+'-----------------------------------------------------------------------------------------------------------\n'
                +Colors.BLUE+'Screenshot-Check\n'
                +Colors.YELLOW+'-----------------------------------------------------------------------------------------------------------\n'
                +Colors.GREEN+f'{strftime("%Y-%m-%d %H:%M:%S")}'+Colors.RESET+f' - {url} - '
                +Colors.CYAN+'It was not possible to take a screenshot. It could be that there is a WAF behind the page.\n'
                +Colors.BLUE+'-----------------------------------------------------------------------------------------------------------\n\n',
                Screen_Dir.replace('Screenshots', 'Logs')
            )
    except MaxRetryError:
        Logs.Log_File(
            Colors.YELLOW+'-----------------------------------------------------------------------------------------------------------\n'
            +Colors.BLUE+'Screenshot-Check\n'
            +Colors.YELLOW+'-----------------------------------------------------------------------------------------------------------\n'
            +Colors.GREEN+f'{strftime("%Y-%m-%d %H:%M:%S")}'+Colors.RESET+f' - {url} - '
            +Colors.CYAN+'It was not possible to connect to the website to take a screenshot\n'
            +Colors.BLUE+'-----------------------------------------------------------------------------------------------------------\n\n',
            Screen_Dir.replace('Screenshots', 'Logs')
        )
    finally:
        driver.quit()

    if (screen_frame_switch == True):
        for Picture in listdir(Screen_Dir):
            if (Screen_Type == "Drawning"):
                raw_image              = imread(join(Screen_Dir, Picture))
                height                 = raw_image.shape[0]
                width                  = raw_image.shape[1]
                start_point, end_point = (-1,-1), (width, height)
                color                  = Screenshot_Color
                img                    = rectangle(raw_image, start_point, end_point, color, int(screenshot_frame_thickness))
                imwrite(join(Screen_Dir, Picture), img)
            elif (Screen_Type == "Border"):
                raw_image              = Image.open(join(Screen_Dir, Picture))
                manipulated_image      = ImageOps.expand(raw_image, border=1, fill='black')
                manipulated_image.save(join(Screen_Dir, Picture))
