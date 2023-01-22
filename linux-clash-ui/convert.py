# 说明 : 本脚本提供批量解析v2ray/ss/ssr/trojan/clash为Clash配置文件,仅供学习交流使用.
# https://github.com/celetor/convert2clash
import os, re, sys, json, base64, datetime
import requests, yaml
import urllib.parse
import random, string


def log(msg):
    time = datetime.datetime.now()
    print('[' + time.strftime('%Y.%m.%d-%H:%M:%S') + '] ' + msg)


# 保存到文件
def save_to_file(file_name, content):
    with open(file_name, 'wb') as f:
        f.write(content)


# 针对url的base64解码
def safe_decode(s):
    num = len(s) % 4
    if num:
        s += '=' * (4 - num)
    return base64.urlsafe_b64decode(s)


# 判断节点有效
def valid_node(name):
    if name.startswith('剩余流量') or name.startswith('套餐到期') or name.startswith('距离下次'):
        return False
    return True


# 解析vmess节点
def decode_v2ray_node(nodes):
    proxy_list = []
    for node in nodes:
        decode_proxy = node[8:]
        if not decode_proxy or decode_proxy.isspace():
            log('vmess节点信息为空，跳过该节点')
            continue
        proxy_str = base64.b64decode(decode_proxy).decode('utf-8')
        proxy_dict = json.loads(proxy_str)
        proxy_list.append(proxy_dict)
    return proxy_list


# 解析ss节点
def decode_ss_node(nodes):
    proxy_list = []
    for node in nodes:
        param = node[5:]
        if not param or param.isspace():
            log('ss节点信息为空，跳过该节点')
            continue
        info = dict()
        if param.find('#') > -1:
            remark = urllib.parse.unquote(param[param.find('#') + 1:])
            info['name'] = remark
            param = param[:param.find('#')]
        if param.find('/?') > -1:
            plugin = urllib.parse.unquote(param[param.find('/?') + 2:])
            param = param[:param.find('/?')]
            for p in plugin.split(';'):
                key_value = p.split('=')
                info[key_value[0]] = key_value[1]
        if param.find('@') > -1:
            matcher = re.match(r'(.*?)@(.*):(.*)', param)
            if matcher:
                param = matcher.group(1)
                info['server'] = matcher.group(2)
                info['port'] = matcher.group(3)
            else:
                continue
            matcher = re.match(r'(.*?):(.*)', safe_decode(param).decode('utf-8'))
            if matcher:
                info['method'] = matcher.group(1)
                info['password'] = matcher.group(2)
            else:
                continue
        else:
            matcher = re.match(r'(.*?):(.*)@(.*):(.*)', safe_decode(param).decode('utf-8'))
            if matcher:
                info['method'] = matcher.group(1)
                info['password'] = matcher.group(2)
                info['server'] = matcher.group(3)
                info['port'] = matcher.group(4)
            else:
                continue
        proxy_list.append(info)
    return proxy_list


# 解析ssr节点
def decode_ssr_node(nodes):
    proxy_list = []
    for node in nodes:
        decode_proxy = node[6:]
        if not decode_proxy or decode_proxy.isspace():
            log('ssr节点信息为空，跳过该节点')
            continue
        proxy_str = safe_decode(decode_proxy).decode('utf-8')
        parts = proxy_str.split(':')
        if len(parts) != 6:
            print('该ssr节点解析失败，链接:{}'.format(node))
            continue
        info = {
            'server': parts[0],
            'port': parts[1],
            'protocol': parts[2],
            'method': parts[3],
            'obfs': parts[4]
        }
        password_params = parts[5].split('/?')
        info['password'] = safe_decode(password_params[0]).decode('utf-8')
        params = password_params[1].split('&')
        for p in params:
            key_value = p.split('=')
            info[key_value[0]] = safe_decode(key_value[1]).decode('utf-8')
        proxy_list.append(info)
    return proxy_list


# 解析trojan节点
def decode_trojan_node(nodes):
    proxy_list = []
    for node in nodes:
        param = node[9:]
        if not param or param.isspace():
            log('trojan节点信息为空，跳过该节点')
            continue
        info = dict()
        if param.find('#') > -1:
            remark = urllib.parse.unquote(param[param.find('#') + 1:])
            info['name'] = remark
            param = param[:param.find('#')]
        matcher = re.match(r'(.*?)@(.*):(\d*)', param)
        if matcher:
            info['password'] = matcher.group(1)
            info['server'] = matcher.group(2)
            info['port'] = matcher.group(3)
            if param.find('sni') > -1:
                param = param[param.find('sni')+4:]
                if param.find('&') > -1:
                    info['sni'] = param[:param.find('&')-1]
                else:
                    info['sni'] = param
        else:
            continue
        proxy_list.append(info)
    return proxy_list


# v2ray转换成Clash节点
def v2ray_to_clash(arr):
    log('v2ray节点转换中...')
    proxies = {
        'proxy_list': [],
        'proxy_names': []
    }
    for item in arr:
        if item.get('ps') is None and item.get('add') is None and item.get('port') is None \
                and item.get('id') is None and item.get('aid') is None:
            continue
        obj = {
            'name': item.get('ps').strip() if item.get('ps') else None,
            'type': 'vmess',
            'server': item.get('add'),
            'port': int(item.get('port')),
            'uuid': item.get('id'),
            'alterId': item.get('aid'),
            'cipher': 'auto',
            'network': item.get('net'),
            'tls': True if item.get('tls') == 'tls' else None,
            'udp': True,
            'ws-opts': {'path': item.get('path'), 'headers': {'Host': item.get('host') if item.get('host') else item.get('add')}}
        }
        for key in list(obj.keys()):
            if obj.get(key) is None:
                del obj[key]
        if obj.get('name'):
            if obj.get('alterId') is not None and valid_node(obj['name']):
                proxies['proxy_list'].append(obj)
                proxies['proxy_names'].append(obj['name'])
    log('可用v2ray节点{}个'.format(len(proxies['proxy_names'])))
    return proxies


# ss转换成Clash节点
def ss_to_clash(arr):
    log('ss节点转换中...')
    proxies = {
        'proxy_list': [],
        'proxy_names': []
    }
    for item in arr:
        obj = {
            'name': item.get('name').strip() if item.get('name') else None,
            'type': 'ss',
            'server': item.get('server'),
            'port': int(item.get('port')),
            'cipher': item.get('method'),
            'password': item.get('password'),
            'plugin': 'obfs' if item.get('plugin') and item.get('plugin').startswith('obfs') else None,
            'plugin-opts': {} if item.get('plugin') else None
        }
        if item.get('obfs'):
            obj['plugin-opts']['mode'] = item.get('obfs')
        if item.get('obfs-host'):
            obj['plugin-opts']['host'] = item.get('obfs-host')
        for key in list(obj.keys()):
            if obj.get(key) is None:
                del obj[key]
        if obj.get('name'):
            if valid_node(obj['name']):
                proxies['proxy_list'].append(obj)
                proxies['proxy_names'].append(obj['name'])
    log('可用ss节点{}个'.format(len(proxies['proxy_names'])))
    return proxies


# ssr转换成Clash节点
def ssr_to_clash(arr):
    log('ssr节点转换中...')
    proxies = {
        'proxy_list': [],
        'proxy_names': []
    }
    for item in arr:
        obj = {
            'name': item.get('remarks').strip() if item.get('remarks') else None,
            'type': 'ssr',
            'server': item.get('server'),
            'port': int(item.get('port')),
            'cipher': item.get('method'),
            'password': item.get('password'),
            'obfs': item.get('obfs'),
            'protocol': item.get('protocol'),
            'obfs-param': item.get('obfsparam'),
            'protocol-param': item.get('protoparam'),
            'udp': True
        }
        for key in list(obj.keys()):
            if obj.get(key) is None:
                del obj[key]
        if obj.get('name'):
            if valid_node(obj['name']):
                proxies['proxy_list'].append(obj)
                proxies['proxy_names'].append(obj['name'])
    log('可用ssr节点{}个'.format(len(proxies['proxy_names'])))
    return proxies


# trojan转换成Clash节点
def trojan_to_clash(arr):
    log('trojan节点转换中...')
    proxies = {
        'proxy_list': [],
        'proxy_names': []
    }
    for item in arr:
        obj = {
            'name': item.get('name').strip() if item.get('name') else None,
            'type': 'trojan',
            'server': item.get('server'),
            'port': int(item.get('port')),
            'password': item.get('password'),
            'sni': item.get('sni').strip() if item.get('sni') else None,
            'skip-cert-verify': False,
            'udp': True
        }
        if re.match(r'((25[0-5]|2[0-4]\d|((1\d{2})|([1-9]?\d)))\.){3}(25[0-5]|2[0-4]\d|((1\d{2})|([1-9]?\d)))', obj['server']) and obj['sni'] is None:
            obj['skip-cert-verify'] = True
        for key in list(obj.keys()):
            if obj.get(key) is None:
                del obj[key]
        if obj.get('name'):
            if valid_node(obj['name']):
                proxies['proxy_list'].append(obj)
                proxies['proxy_names'].append(obj['name'])
    log('可用trojan节点{}个'.format(len(proxies['proxy_names'])))
    return proxies


# 获取节点数据:
def get_proxies(urls):
    if urls is None or urls == '':
        sys.exit()
    url_list = urls.split(';')
    headers = {
        'User-Agent': 'Clash'
    }
    proxy_list = {
        'proxy_list': [],
        'proxy_names': []
    }
    for url in url_list:
        print(url)
        if url.startswith('http'):
            try:
                inputnode = requests.get(url, headers=headers, timeout=5).text
            except Exception as r:
                log('获取订阅链接{}失败:{}'.format(url,r))
                continue
        else:
            try:
                f = open(url, 'r', encoding="utf-8")
                inputnode = f.read()
                f.close()
            except FileNotFoundError:
                log('本地节点{}导入失败'.format(url))
                continue

        # 提取节点
        if(not((inputnode.startswith('vmess://'))or(inputnode.startswith('ss://'))or(inputnode.startswith('ssr://'))or(inputnode.startswith('trojan://')))):
            try:
                inputnode = base64.b64decode(inputnode).decode('utf-8')
            except Exception as r:
                log('base64解码失败:{},应当为clash节点'.format(r))
                log('clash节点提取中...')
                yml = yaml.load(inputnode, Loader=yaml.FullLoader)
                nodes_list = []
                tmp_list = []
                # clash新字段
                if yml.get('proxies'):
                    tmp_list = yml.get('proxies')
                else:
                    log('clash节点提取失败,clash节点为空')
                    sys.exit()
                for node in tmp_list:
                    if node.get('name'):
                        if valid_node(node['name']):
                            nodes_list.append(node)
                node_names = [node.get('name') for node in nodes_list]
                log('可用clash节点{}个'.format(len(node_names)))
                proxy_list['proxy_list'].extend(nodes_list)
                proxy_list['proxy_names'].extend(node_names)
                continue

        nodes_list = inputnode.splitlines()
        v2ray_urls = []
        ss_urls = []
        ssr_urls = []
        trojan_urls = []
        for node in nodes_list:
            if node.startswith('vmess://'):
                v2ray_urls.append(node)
            elif node.startswith('ss://'):
                ss_urls.append(node)
            elif node.startswith('ssr://'):
                ssr_urls.append(node)
            elif node.startswith('trojan://'):
                trojan_urls.append(node)
            else:
                pass
        clash_node = []
        if len(v2ray_urls) > 0:
            decode_proxy = decode_v2ray_node(v2ray_urls)
            clash_node = v2ray_to_clash(decode_proxy)
            proxy_list['proxy_list'].extend(clash_node['proxy_list'])
            proxy_list['proxy_names'].extend(clash_node['proxy_names'])
        if len(ss_urls) > 0:
            decode_proxy = decode_ss_node(ss_urls)
            clash_node = ss_to_clash(decode_proxy)
            proxy_list['proxy_list'].extend(clash_node['proxy_list'])
            proxy_list['proxy_names'].extend(clash_node['proxy_names'])
        if len(ssr_urls) > 0:
            decode_proxy = decode_ssr_node(ssr_urls)
            clash_node = ssr_to_clash(decode_proxy)
            proxy_list['proxy_list'].extend(clash_node['proxy_list'])
            proxy_list['proxy_names'].extend(clash_node['proxy_names'])
        if len(trojan_urls) > 0:
            decode_proxy = decode_trojan_node(trojan_urls)
            clash_node = trojan_to_clash(decode_proxy)
            proxy_list['proxy_list'].extend(clash_node['proxy_list'])
            proxy_list['proxy_names'].extend(clash_node['proxy_names'])

    log('共发现:{}个节点'.format(len(proxy_list['proxy_names'])))
    return proxy_list


# 获取本地规则策略的配置文件
def load_local_config(path):
    try:
        f = open(path, 'r', encoding="utf-8")
        local_config = yaml.load(f.read(), Loader=yaml.FullLoader)
        f.close()
        return local_config
    except FileNotFoundError:
        log('本地配置文件加载失败')


# 获取规则策略的配置文件
def get_default_config(path, url):
    template_config = load_local_config(path)
    if not template_config :
        log('加载网络配置文件')
        try:
            raw = requests.get(url, timeout=5).content.decode('utf-8')
            template_config = yaml.load(raw, Loader=yaml.FullLoader)
        except requests.exceptions.RequestException:
            log('获取网络规则配置失败')
            sys.exit()
    log('已获取规则配置文件')
    return template_config


# 将代理添加到配置文件
def add_proxies_to_model(data, model):
    model['proxies'] = data.get('proxy_list')
    for group in model.get('proxy-groups'):
        if group.get('proxies') is None:
            group['proxies'] = data.get('proxy_names')
        else:
            group['proxies'].extend(data.get('proxy_names'))
    words = string.digits + string.ascii_lowercase + string.ascii_uppercase
    model['secret'] = "".join(random.choice(words) for _ in range(30))
    if model['authentication'] is None:
        username = "".join(random.choice(words) for _ in range(6))
        userpass = "".join(random.choice(words) for _ in range(30))
        auth = username + ':' + userpass
        auths = []
        auths.append(auth)
        model['authentication']=auths
    return model


# 保存配置文件
def save_config(path, data):
    if len(data['proxies'])==0 :
        sys.exit()
    print('external controller password:{}'.format(data['secret']))
    print('authentication:{}'.format(data['authentication']))
    config = yaml.dump(data, sort_keys=False, default_flow_style=False, encoding='utf-8', allow_unicode=True)
    save_to_file(path, config)
    log('成功更新{}个节点'.format(len(data['proxies'])))


# 程序入口
if __name__ == '__main__':
    # 输出路径
    output_path = './config.yaml'
    # 规则策略
    config_path = './sample.yaml'
    config_url = 'https://raw.fastgit.org/veeyoung/convert2clash/master/sample.yaml'

    default_config = get_default_config(config_path, config_url)
    input_urls = input('请输入文件名或订阅地址(多个用;隔开):')
    node_list = get_proxies(input_urls)
    final_config = add_proxies_to_model(node_list, default_config)
    save_config(output_path, final_config)
    print(f'文件已导出至 {output_path}')
