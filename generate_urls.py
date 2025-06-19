#!/usr/bin/env python3
"""
为每个镜像源文件夹生成urls.json文件

该脚本会扫描tv目录下的每个数字文件夹，为每个文件夹生成一个包含所有配置文件的urls.json文件。
"""

import json
import os
from pathlib import Path
from typing import List, Dict
import logging

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

# 镜像源列表（与config.py保持一致）
MIRROR_SOURCES = [
    "https://ghproxy.net/https://raw.githubusercontent.com",
    "https://raw.kkgithub.com",
    "https://gcore.jsdelivr.net/gh",
    "https://mirror.ghproxy.com/https://raw.githubusercontent.com",
    "https://github.moeyy.xyz/https://raw.githubusercontent.com",
    "https://fastly.jsdelivr.net/gh",
    ""  # 原始源
]

def get_config_name_from_filename(filename: str) -> str:
    """从文件名获取配置名称"""
    # 移除.json扩展名，直接返回文件名
    return filename.replace('.json', '')

def generate_urls_for_mirror(mirror_index: int, mirror_url: str, tv_dir: Path) -> None:
    """为指定镜像源生成urls.json文件"""
    mirror_dir = tv_dir / str(mirror_index)
    
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
        config_name = get_config_name_from_filename(json_file.name)
        
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

def main():
    """主函数"""
    tv_dir = Path("./tv")
    
    if not tv_dir.exists():
        logger.error("tv目录不存在")
        return
    
    logger.info("开始为每个镜像源生成urls.json文件...")
    
    # 为每个镜像源生成urls.json
    for mirror_index, mirror_url in enumerate(MIRROR_SOURCES):
        logger.info(f"处理镜像源 {mirror_index}: {mirror_url or '原始源'}")
        generate_urls_for_mirror(mirror_index, mirror_url, tv_dir)
    
    logger.info("所有urls.json文件生成完成！")

if __name__ == "__main__":
    main() 