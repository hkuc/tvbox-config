#!/usr/bin/env python3
"""
TvBox配置构建工具

该脚本用于从GitHub获取TvBox配置文件，并将其镜像到多个CDN源，
以解决电视设备访问GitHub的问题。
"""

import re
import datetime
import requests
import json
import urllib3
import os
from pathlib import Path
from typing import List, Dict, Optional, Tuple
from tqdm import tqdm
from Crypto.Cipher import AES
import base64
import logging
from config import (
    MIRROR_SOURCES, GITHUB_URLS, SPECIAL_CONFIGS, PATH_REPLACEMENTS,
    PATHS, REQUEST_CONFIG, LOGGING_CONFIG, README_TEMPLATE
)

# 配置日志
logging.basicConfig(
    level=getattr(logging, LOGGING_CONFIG["level"]), 
    format=LOGGING_CONFIG["format"]
)
logger = logging.getLogger(__name__)

# 禁用SSL警告
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class TqdmColored(tqdm):
    """带颜色的进度条类"""
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.bar_format = '{l_bar}%s{bar}%s{r_bar}' % ('\x1b[47m\x1b[32m', '\x1b[0m')


class ConfigProcessor:
    """配置处理器类"""
    
    def __init__(self, output_dir: str = PATHS["output_dir"]):
        self.output_dir = Path(output_dir)
        self.session = requests.Session()
        self.session.verify = REQUEST_CONFIG["verify_ssl"]
    
    def create_directory(self, path: Path) -> None:
        """创建目录"""
        path.mkdir(parents=True, exist_ok=True)
    
    def get_data(self, url: str) -> str:
        """获取URL内容"""
        try:
            if url.startswith("http"):
                response = self.session.get(url, timeout=REQUEST_CONFIG["timeout"])
                response.raise_for_status()
                return response.text
            return ""
        except requests.RequestException as e:
            logger.error(f"获取数据失败: {url}, 错误: {e}")
            raise
    
    def is_valid_json(self, json_str: str) -> bool:
        """验证JSON格式"""
        try:
            json.loads(json_str)
            return True
        except json.JSONDecodeError:
            return False
    
    def pad_end(self, key: str) -> str:
        """填充密钥到16位"""
        return key + "0000000000000000"[:16 - len(key)]
    
    def extract_base64(self, data: str) -> str:
        """提取Base64编码的数据"""
        match = re.search(r"[A-Za-z0-9]{8}\*\*", data)
        return data[data.index(match.group()) + 10:] if match else ""
    
    def base64_decode(self, data: str) -> str:
        """Base64解码"""
        try:
            extract = self.extract_base64(data)
            if extract:
                return base64.b64decode(extract).decode("utf-8")
            return data
        except Exception as e:
            logger.warning(f"Base64解码失败: {e}")
            return data
    
    def ecb_decrypt(self, data: str, key: str) -> str:
        """ECB模式解密"""
        try:
            spec = AES.new(self.pad_end(key).encode(), AES.MODE_ECB)
            return spec.decrypt(bytes.fromhex(data)).decode("utf-8")
        except Exception as e:
            logger.error(f"ECB解密失败: {e}")
            raise
    
    def cbc_decrypt(self, data: str) -> str:
        """CBC模式解密"""
        try:
            decode = bytes.fromhex(data).decode().lower()
            key = self.pad_end(decode[decode.index("$#") + 2:decode.index("#$")])
            iv = self.pad_end(decode[-13:])
            key_spec = AES.new(key.encode(), AES.MODE_CBC, iv.encode())
            data = data[data.index("2324") + 4:-26]
            decrypt_data = key_spec.decrypt(bytes.fromhex(data))
            return decrypt_data.decode("utf-8")
        except Exception as e:
            logger.error(f"CBC解密失败: {e}")
            raise
    
    def get_json(self, url: str) -> str:
        """获取并处理JSON数据"""
        # 解析URL和密钥
        parts = url.split(";")
        key = parts[2] if len(parts) > 2 else ""
        url = parts[0]
        
        # 获取原始数据
        data = self.get_data(url)
        if not data:
            raise ValueError(f"无法获取数据: {url}")
        
        # 处理数据
        if self.is_valid_json(data):
            return data
        
        if "**" in data:
            data = self.base64_decode(data)
        
        if data.startswith("2423"):
            data = self.cbc_decrypt(data)
        
        if key:
            data = self.ecb_decrypt(data, key)
        
        return data
    
    def get_ext(self, ext: str) -> str:
        """获取扩展数据"""
        try:
            return self.base64_decode(self.get_data(ext[4:]))
        except Exception as e:
            logger.warning(f"获取扩展数据失败: {e}")
            return ""
    
    def process_url_replacements(self, content: str, mirror_url: str, url_path: str, config_name: str) -> str:
        """处理URL替换"""
        processed_content = content
        
        # 处理路径替换（除了特殊配置）
        if config_name not in SPECIAL_CONFIGS:
            # 处理相对路径替换
            processed_content = processed_content.replace("'./", f"'{url_path}") \
                                               .replace('"./', f'"{url_path}')
            
            # 处理配置的路径替换
            for old_path, replacement_type in PATH_REPLACEMENTS.items():
                if replacement_type == "url_path":
                    processed_content = processed_content.replace(old_path, url_path)
                else:
                    # 可以扩展其他替换类型
                    processed_content = processed_content.replace(old_path, replacement_type)
        
        # 处理镜像源替换
        if mirror_url:
            if 'jsdelivr' in mirror_url:
                processed_content = processed_content.replace("/raw/", "@")
            else:
                processed_content = processed_content.replace("/raw/", "/")
                for github_url in GITHUB_URLS:
                    processed_content = processed_content.replace(f"'{github_url}", f"'{mirror_url}") \
                                                       .replace(f'"{github_url}', f'"{mirror_url}')
        
        return processed_content
    
    def save_config(self, content: str, mirror_index: int, config_name: str) -> None:
        """保存配置文件"""
        output_path = self.output_dir / str(mirror_index) / f"{config_name}.json"
        self.create_directory(output_path.parent)
        
        try:
            with open(output_path, "w", encoding="utf-8") as f:
                f.write(content)
        except IOError as e:
            logger.error(f"保存配置文件失败: {output_path}, 错误: {e}")
            raise
    
    def process_configs(self, configs: List[Dict[str, str]]) -> None:
        """处理所有配置"""
        with TqdmColored(total=len(configs), desc="构建配置文件") as progress_bar:
            for config in configs:
                try:
                    # 获取JSON数据
                    json_content = self.get_json(config["url"])
                    
                    # 为每个镜像源处理配置
                    for mirror_index, mirror_url in enumerate(MIRROR_SOURCES):
                        processed_content = self.process_url_replacements(
                            json_content, 
                            mirror_url, 
                            config["path"], 
                            config["name"]
                        )
                        
                        self.save_config(processed_content, mirror_index, config["name"])
                    
                    progress_bar.update(1)
                    
                except Exception as e:
                    logger.error(f"处理配置失败: {config['name']}, 错误: {e}")
                    progress_bar.update(1)
                    continue
    
    def get_config_name_from_filename(self, filename: str) -> str:
        """从文件名获取配置名称"""
        # 移除.json扩展名，直接返回文件名
        return filename.replace('.json', '')
    
    def generate_urls_for_mirror(self, mirror_index: int, mirror_url: str) -> None:
        """为指定镜像源生成urls.json文件"""
        mirror_dir = self.output_dir / str(mirror_index)
        
        if not mirror_dir.exists():
            logger.warning(f"镜像源目录不存在: {mirror_dir}")
            return
        
        # 获取目录下的所有JSON文件，排除urls.json
        json_files = [f for f in mirror_dir.glob("*.json") if f.name != "urls.json"]
        
        if not json_files:
            logger.warning(f"镜像源目录 {mirror_dir} 中没有找到JSON文件")
            return
        
        urls = []
        
        for json_file in json_files:
            config_name = self.get_config_name_from_filename(json_file.name)
            
            # 构建URL
            if mirror_url:
                # 使用镜像源URL
                if 'jsdelivr' in mirror_url:
                    # jsdelivr格式
                    url = f"{mirror_url}/hkuc/tvbox-config@main/tv/{mirror_index}/{json_file.name}"
                else:
                    # 其他镜像源格式
                    url = f"{mirror_url}/hkuc/tvbox-config/main/tv/{mirror_index}/{json_file.name}"
            else:
                # 原始GitHub URL
                url = f"https://raw.githubusercontent.com/hkuc/tvbox-config/main/tv/{mirror_index}/{json_file.name}"
            
            urls.append({
                "url": url,
                "name": config_name
            })
        
        # 生成urls.json文件
        urls_data = {"urls": urls}
        urls_file = mirror_dir / "urls.json"
        
        try:
            with open(urls_file, 'w', encoding='utf-8') as f:
                json.dump(urls_data, f, ensure_ascii=False, indent=2)
            logger.info(f"已生成 {urls_file}，包含 {len(urls)} 个配置")
        except Exception as e:
            logger.error(f"生成 {urls_file} 失败: {e}")
    
    def generate_all_urls(self) -> None:
        """为所有镜像源生成urls.json文件"""
        logger.info("开始为每个镜像源生成urls.json文件...")
        
        for mirror_index, mirror_url in enumerate(MIRROR_SOURCES):
            logger.info(f"处理镜像源 {mirror_index}: {mirror_url or '原始源'}")
            self.generate_urls_for_mirror(mirror_index, mirror_url)
        
        logger.info("所有urls.json文件生成完成！")


class ReadmeGenerator:
    """README生成器类"""
    
    @staticmethod
    def generate_readme() -> None:
        """生成README文件"""
        now = datetime.datetime.now()
        
        readme_content = README_TEMPLATE.format(
            update_time=now.strftime("%Y-%m-%d %H:%M:%S")
        )
        
        try:
            with open(PATHS["readme_file"], "w", encoding="utf-8") as f:
                f.write(readme_content)
            logger.info("README.md 生成成功")
        except IOError as e:
            logger.error(f"生成README失败: {e}")
            raise


def load_configs(config_file: str = PATHS["config_file"]) -> List[Dict[str, str]]:
    """加载配置文件"""
    try:
        with open(config_file, 'r', encoding='utf-8') as f:
            return json.load(f)
    except (IOError, json.JSONDecodeError) as e:
        logger.error(f"加载配置文件失败: {config_file}, 错误: {e}")
        raise


def main():
    """主函数"""
    try:
        logger.info("开始构建TvBox配置...")
        
        # 加载配置
        configs = load_configs()
        logger.info(f"加载了 {len(configs)} 个配置")
        
        # 处理配置
        processor = ConfigProcessor()
        processor.process_configs(configs)
        
        # 生成README
        ReadmeGenerator.generate_readme()
        
        # 生成urls.json文件
        processor.generate_all_urls()
        
        logger.info("构建完成！")
        
    except Exception as e:
        logger.error(f"构建失败: {e}")
        raise


if __name__ == "__main__":
    main()