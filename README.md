# Docker Blessing Skin Server

## Get Started

1. Make sure there is a mysql instance in the same network of blessing skin container. 
2. Run by `docker run -e tz='Asia/Shanghai' -v ${path}:/var/www/html chuanwise/blessing-skin-server:6.0.2`. 

## Build

1. Download the Blessing Skin Server from [releases](https://github.com/bs-community/blessing-skin-server/releases). 
2. Uncompressed them into `./src`. Make sure there are `index.php` in `./src/public`. 
3. Build image by `docker build . -t ${image}`. 
