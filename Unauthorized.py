import requests
import argparse
import socket
import urllib3
import ftplib
import platform
import os
import sys
import pymongo
import threading
import config
from ldap3 import Connection, Server, ALL
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

headers = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:61.0) Gecko/20100101 Firefox/61.0'
}

RabbitMQheaders = {
    'authorization': 'Basic Z3Vlc3Q6Z3Vlc3Q=',
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
}



def ActiveMQ(target):
    url = target + config.ActiveMQVuln
    try:
        basicAuth = requests.get(url, headers, verify=False, auth=('admin', 'admin'))
        if basicAuth.status_code == 200 and "Version" in basicAuth.text:
            print("[!]ActiveMQ Unauthorized", url)
    except Exception:
        pass


def AtlassianCrowd(target):
    url = target + config.AtlassianCrowdVuln
    try:
        vuln = requests.get(url, headers, verify=False)
        if vuln.status_code == 400:
            print("[!]AtlassianCrowd Unauthorized(RCE https://github.com/jas502n/CVE-2019-11580)", url)
    except Exception:
        pass


def CouchDB(target):
    url = target + config.CouchDBVuln
    try:
        vuln = requests.get(url, headers, verify=False)
        if vuln.status_code == 200 and "version" in vuln.text:
            print("[!] CouchDB Unauthorized", url)
    except Exception:
        pass


def DockerAPI(target):
    url = target + config.DockerAPIVuln
    try:
        vuln = requests.get(url, headers, verify=False)
        if vuln.status_code == 200 and "Version" in vuln.text:
            print("[!] DockerAPI Unauthorized", url)
    except Exception:
        pass


def Dubbo(target):
    url = target.replace("http://", "")
    if "https://" in target:
        url = target.replace("https://", "")
    ip = socket.gethostbyname(url)
    try:
        socket.setdefaulttimeout(5)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((ip, config.DubboVuln))
        s.send(bytes("status -l\r\n", 'UTF-8'))
        result = s.recv(1024).decode()
        if "server" in result:
            print("[!] Dubbo Unauthorized", ip)
        s.close()
    except Exception:
        pass


def Druid(target):
    url = target + config.DruidVuln
    try:
        vuln = requests.get(url, headers, verify=False)
        if vuln.status_code == 200 and "Druid Stat Index" in vuln.text:
            print("[!] Druid Unauthorized", url)
    except Exception:
        pass


def Elasticsearch(target):
    url = target + config.ElasticsearchVuln
    try:
        vuln = requests.get(url, headers, verify=False)
        if vuln.status_code == 200 and "/_cat/master" in vuln.text:
            print("[!] Elasticsearch Unauthorized", url)
    except Exception:
        pass


def Ftp(target):
    url = target.replace("http://", "")
    if "https://" in target:
        url = target.replace("https://", "")
    ip = socket.gethostbyname(url)
    try:
        ftp = ftplib.FTP()
        ftp.connect(ip, config.FtpVuln)
        ftp.login("anonymous", "anonymous")
        print("[!] FTP Unauthorized", ip)
    except Exception:
        pass


def HadoopYARN(target):
    url = target + config.HadoopYARNVuln
    try:
        vuln = requests.get(url, headers, verify=False)
        if vuln.status_code == 200 and "All Applications" in vuln.text:
            print("[!] HadoopYARN Unauthorized", url)
    except Exception:
        pass


def JBoss(target):
    url = target + config.JBossVuln
    try:
        vuln = requests.get(url, headers, verify=False)
        if vuln.status_code == 200 and "JBoss JMX Management Console" in vuln.text:
            print("[!] JBoss Unauthorized", url)
    except Exception:
        pass


def Jenkins(target):
    url = target + config.JenkinsVuln
    try:
        vuln = requests.get(url, headers, verify=False)
        if vuln.status_code == 200 and "Jenkins-Crumb" in vuln.text:
            print("[!] Jenkins Unauthorized", url)
    except Exception:
        pass


def JupyterNotebook(target):
    url = target + config.JupyterNotebookVuln
    try:
        vuln = requests.get(url, headers, verify=False)
        if vuln.status_code == 200 and "Jupyter Notebook" in vuln.text:
            print("[!] JupyterNotebook Unauthorized", url)
    except Exception:
        pass


def Kibana(target):
    url = target + config.Kibanavuln
    try:
        vuln = requests.get(url, headers, verify=False)
        if vuln.status_code == 200 and "Visualize" in vuln.text:
            print("[!] Kibana Unauthorized", url)
    except Exception:
        pass


def KubernetesApiServer(target):
    url = target + config.KubernetesApiServervuln
    try:
        vuln = requests.get(url, headers, verify=False)
        if vuln.status_code == 200 and "paths" in vuln.text and "/api" in vuln.text:
            print("[!] KubernetesApiServer", url)
    except Exception:
        pass


def ldap_anonymous(target):
    url = target.replace("http://", "")
    if "https://" in target:
        url = target.replace("https://", "")
    try:
        server = Server(url, get_info=ALL, connect_timeout=1)
        conn = Connection(server, auto_bind=True)
        print("[+] ldap login for anonymous")
        conn.closed()
    except Exception:
        pass


def Weblogic(target):
    url = target + config.Weblogicvuln
    try:
        vuln = requests.get(url, headers, verify=False)
        if vuln.status_code == 200 and "管理控制台主页" in vuln.text and "注销" in vuln.text:
            print("[!] Weblogic Unauthorized", url)
    except Exception:
        pass


def Solr(target):
    url = target + config.Solrvuln
    try:
        vuln = requests.get(url, headers, verify=False)
        if vuln.status_code == 200 and "Collections" in vuln.text and "Cloud" in vuln.text:
            print("[!] Solr Unauthorized", url)
    except Exception:
        pass


def Springboot(target):
    try:
        url = target + config.Springbootvuln
        vuln = requests.get(url, headers, verify=False)
        if vuln.status_code == 200 and "/info" in vuln.text and "/health" in vuln.text:
            print("[!] SpringbootActuator Unauthorized", url)
    except Exception:
        pass


def RabbitMQ(target):
    url = target + config.RabbitMQvuln
    try:
        vuln = requests.get(url, headers=RabbitMQheaders, verify=False)
        if vuln.status_code == 200 and "guest" in vuln.text:
            print("[!] RabbitMQ Unauthorized", url)
    except Exception:
        pass


def Zabbix(target):
    url = target + config.Zabbixvuln
    try:
        vuln = requests.get(url, headers=RabbitMQheaders, verify=False)
        if vuln.status_code == 200 and "Latest data" in vuln.text:
            print("[!] RabbitMQ Unauthorized", url)
    except Exception:
        pass


def Redis(target):
    url = target.replace("http://", "")
    if "https://" in target:
        url = target.replace("https://", "")
    ip = socket.gethostbyname(url)
    try:
        socket.setdefaulttimeout(10)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((ip, config.Redisvuln))
        s.send(bytes("INFO\r\n", 'UTF-8'))
        result = s.recv(1024).decode()
        if "redis_version" in result:
            print("[!] Redis Unauthorized", ip)
        s.close()
    except Exception:
        pass


def Rsync(target):
    url = target.replace("http://", "")
    if "https://" in target:
        url = target.replace("https://", "")
    if "Linux" in platform.platform():
        rsynctext = "rsync  " + "rsync://" + url + config.Rsyncvuln
        result = os.popen(rsynctext)
        bool = False
        for line in result:
            if "Password:" in line:
                bool = True
                return
        if bool:
            print("[!] Rsync Unauthorized", url)
    else:
        print("[*] Windows does not support Rsync unauthorized scanning")


def NFS(target):
    url = target.replace("http://", "")
    if "https://" in target:
        url = target.replace("https://", "")
    if "Linux" in platform.platform():
        rsynctext = "showmount  -e  " + url
        result = os.popen(rsynctext)
        for line in result:
            if "Export list" in line:
                print("[!] NFS Unauthorized", url)
                return
    else:
        print("[*] Windows does not support NFS unauthorized scanning")


def Memcache(target):
    url = target.replace("http://", "")
    if "https://" in target:
        url = target.replace("https://", "")
    ip = socket.gethostbyname(url)
    try:
        socket.setdefaulttimeout(10)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((ip, config.Memcachevuln))
        s.send(bytes("stats\r\n", 'UTF-8'))
        result = s.recv(1024).decode()
        if "STAT version" in result:
            print("[!] Memcachevuln Unauthorized", ip)
        s.close()
    except Exception:
        pass


def MongoDB(target):
    try:
        conn = pymongo.MongoClient(target, config.MongoDBvuln, socketTimeoutMS=3000)
        dbname = conn.database_names()
        if dbname:
            print("[!] MongoDB Unauthorized")
    except Exception:
        pass


def Zookeeper(target):
    url = target.replace("http://", "")
    if "https://" in target:
        url = target.replace("https://", "")
    ip = socket.gethostbyname(url)
    try:
        socket.setdefaulttimeout(10)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((ip, config.Zookeepervuln))
        s.send(bytes("envi\r\n", 'UTF-8'))
        result = s.recv(1024).decode()
        if "Environment" in result:
            print("[!] Zookeeper Unauthorized", ip)
        s.close()
    except Exception:
        pass


def cmd():
    parser = argparse.ArgumentParser(usage="python Unauthorized.py -t http://target.com",
                                     description="集成二十六种未授权访问 [Active MQ ,Atlassian Crowd ,CouchDB ,Docker ,Dubbo ,Druid ,Elasticsearch ,FTP ,Hadoop ,JBoss ,Jenkins ,Jupyter Notebook ,Kibana ,Kubernetes Api Server ,LDAP ,MongoDB ,Memcached ,NFS ,Rsync ,Redis ,RabbitMQ ,Solr ,Spring Boot Actuator ,Weblogic ,ZooKeeper ,Zabbix]")
    parser.add_argument("-t", "--target", help="Set Target", type=str)
    args = parser.parse_args()
    return args


if __name__ == '__main__':
    if len(sys.argv) == 1:
        print("Usage: python Unauthorized.py -h")
        sys.exit()
    args = cmd()
    target = args.target
    if target[-1] == "/":
        target = sys.argv[1].strip("/")
    functionname = [ActiveMQ, AtlassianCrowd, CouchDB, DockerAPI, Dubbo, Druid,
                    Elasticsearch, Ftp, HadoopYARN, JBoss, Jenkins, JupyterNotebook,
                    Kibana, KubernetesApiServer, ldap_anonymous, Weblogic, Solr, Springboot,
                    RabbitMQ, Zabbix, Redis, Rsync, NFS, Memcache, MongoDB, Zookeeper
                    ]
    for func in functionname:
        thread = threading.Thread(target=func, args=(target,))
        thread.start()
