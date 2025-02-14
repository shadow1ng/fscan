package Common

import (
	"fmt"
	"strings"
)

// 支持的语言类型
const (
	LangZH = "zh" // 中文
	LangEN = "en" // 英文
	LangJA = "ja" // 日文
	LangRU = "ru" // 俄文
)

// 多语言文本映射
var i18nMap = map[string]map[string]string{
	"output_init_start": {
		LangZH: "开始初始化输出系统",
		LangEN: "Starting output system initialization",
		LangJA: "出力システムの初期化を開始",
		LangRU: "Начало инициализации системы вывода",
	},
	"output_format_invalid": {
		LangZH: "无效的输出格式: %s",
		LangEN: "Invalid output format: %s",
		LangJA: "無効な出力形式: %s",
		LangRU: "Неверный формат вывода: %s",
	},
	"output_path_empty": {
		LangZH: "输出路径不能为空",
		LangEN: "Output path cannot be empty",
		LangJA: "出力パスは空にできません",
		LangRU: "Путь вывода не может быть пустым",
	},
	"output_create_dir_failed": {
		LangZH: "创建输出目录失败: %v",
		LangEN: "Failed to create output directory: %v",
		LangJA: "出力ディレクトリの作成に失敗: %v",
		LangRU: "Не удалось создать каталог вывода: %v",
	},
	"output_init_failed": {
		LangZH: "初始化输出系统失败: %v",
		LangEN: "Failed to initialize output system: %v",
		LangJA: "出力システムの初期化に失敗: %v",
		LangRU: "Не удалось инициализировать систему вывода: %v",
	},
	"output_init_success": {
		LangZH: "输出系统初始化成功",
		LangEN: "Output system initialized successfully",
		LangJA: "出力システムの初期化に成功",
		LangRU: "Система вывода успешно инициализирована",
	},
	"output_already_init": {
		LangZH: "输出系统已经初始化",
		LangEN: "Output system already initialized",
		LangJA: "出力システムは既に初期化されています",
		LangRU: "Система вывода уже инициализирована",
	},
	"output_opening_file": {
		LangZH: "正在打开输出文件: %s",
		LangEN: "Opening output file: %s",
		LangJA: "出力ファイルを開いています: %s",
		LangRU: "Открытие файла вывода: %s",
	},
	"output_open_file_failed": {
		LangZH: "打开输出文件失败: %v",
		LangEN: "Failed to open output file: %v",
		LangJA: "出力ファイルを開くのに失敗: %v",
		LangRU: "Не удалось открыть файл вывода: %v",
	},
	"output_init_csv": {
		LangZH: "初始化CSV输出",
		LangEN: "Initializing CSV output",
		LangJA: "CSV出力を初期化中",
		LangRU: "Инициализация вывода CSV",
	},
	"output_write_csv_header_failed": {
		LangZH: "写入CSV头失败: %v",
		LangEN: "Failed to write CSV header: %v",
		LangJA: "CSVヘッダーの書き込みに失敗: %v",
		LangRU: "Не удалось записать заголовок CSV: %v",
	},
	"output_init_json": {
		LangZH: "初始化JSON输出",
		LangEN: "Initializing JSON output",
		LangJA: "JSON出力を初期化中",
		LangRU: "Инициализация вывода JSON",
	},
	"output_init_txt": {
		LangZH: "初始化文本输出",
		LangEN: "Initializing text output",
		LangJA: "テキスト出力を初期化中",
		LangRU: "Инициализация текстового вывода",
	},
	"output_init_complete": {
		LangZH: "输出系统初始化完成",
		LangEN: "Output system initialization complete",
		LangJA: "出力システムの初期化が完了",
		LangRU: "Инициализация системы вывода завершена",
	},
	"output_not_init": {
		LangZH: "输出系统未初始化",
		LangEN: "Output system not initialized",
		LangJA: "出力システムが初期化されていません",
		LangRU: "Система вывода не инициализирована",
	},
	"output_saving_result": {
		LangZH: "正在保存%s结果: %s",
		LangEN: "Saving %s result: %s",
		LangJA: "%s結果を保存中: %s",
		LangRU: "Сохранение результата %s: %s",
	},
	"output_save_failed": {
		LangZH: "保存结果失败: %v",
		LangEN: "Failed to save result: %v",
		LangJA: "結果の保存に失敗: %v",
		LangRU: "Не удалось сохранить результат: %v",
	},
	"output_save_success": {
		LangZH: "成功保存%s结果: %s",
		LangEN: "Successfully saved %s result: %s",
		LangJA: "%s結果の保存に成功: %s",
		LangRU: "Успешно сохранен результат %s: %s",
	},
	"output_txt_format": {
		LangZH: "[%s] [%s] 目标:%s 状态:%s 详情:%s",
		LangEN: "[%s] [%s] Target:%s Status:%s Details:%s",
		LangJA: "[%s] [%s] ターゲット:%s 状態:%s 詳細:%s",
		LangRU: "[%s] [%s] Цель:%s Статус:%s Подробности:%s",
	},
	"output_no_need_close": {
		LangZH: "输出系统无需关闭",
		LangEN: "No need to close output system",
		LangJA: "出力システムを閉じる必要はありません",
		LangRU: "Нет необходимости закрывать систему вывода",
	},
	"output_closing": {
		LangZH: "正在关闭输出系统",
		LangEN: "Closing output system",
		LangJA: "出力システムを閉じています",
		LangRU: "Закрытие системы вывода",
	},
	"output_flush_csv": {
		LangZH: "正在刷新CSV缓冲",
		LangEN: "Flushing CSV buffer",
		LangJA: "CSVバッファをフラッシュ中",
		LangRU: "Очистка буфера CSV",
	},
	"output_close_failed": {
		LangZH: "关闭输出文件失败: %v",
		LangEN: "Failed to close output file: %v",
		LangJA: "出力ファイルを閉じるのに失敗: %v",
		LangRU: "Не удалось закрыть файл вывода: %v",
	},
	"output_closed": {
		LangZH: "输出系统已关闭",
		LangEN: "Output system closed",
		LangJA: "出力システムが閉じられました",
		LangRU: "Система вывода закрыта",
	},
	"flag_host": {
		LangZH: "指定目标主机,支持以下格式:\n" +
			"  - 单个IP: 192.168.11.11\n" +
			"  - IP范围: 192.168.11.11-255\n" +
			"  - 多个IP: 192.168.11.11,192.168.11.12",

		LangEN: "Specify target host, supports following formats:\n" +
			"  - Single IP: 192.168.11.11\n" +
			"  - IP Range: 192.168.11.11-255\n" +
			"  - Multiple IPs: 192.168.11.11,192.168.11.12",

		LangJA: "ターゲットホストを指定、以下の形式をサポート:\n" +
			"  - 単一IP: 192.168.11.11\n" +
			"  - IP範囲: 192.168.11.11-255\n" +
			"  - 複数IP: 192.168.11.11,192.168.11.12",

		LangRU: "Укажите целевой хост, поддерживаются следующие форматы:\n" +
			"  - Один IP: 192.168.11.11\n" +
			"  - Диапазон IP: 192.168.11.11-255\n" +
			"  - Несколько IP: 192.168.11.11,192.168.11.12",
	},
	"flag_ports": {
		LangZH: "指定扫描端口,支持以下格式:\n" +
			"格式:\n" +
			"  - 单个: 22\n" +
			"  - 范围: 1-65535\n" +
			"  - 多个: 22,80,3306\n" +
			"预设组:\n" +
			"  - main: 常用端口组\n" +
			"  - service: 服务端口组\n" +
			"  - db: 数据库端口组\n" +
			"  - web: Web端口组\n" +
			"  - all: 全部端口\n" +
			"示例: -p main, -p 80,443, -p 1-1000",

		LangEN: "Specify scan ports, supports:\n" +
			"Format:\n" +
			"  - Single: 22\n" +
			"  - Range: 1-65535\n" +
			"  - Multiple: 22,80,3306\n" +
			"Presets:\n" +
			"  - main: Common ports\n" +
			"  - service: Service ports\n" +
			"  - db: Database ports\n" +
			"  - web: Web ports\n" +
			"  - all: All ports\n" +
			"Example: -p main, -p 80,443, -p 1-1000",

		LangJA: "スキャンポートを指定:\n" +
			"形式:\n" +
			"  - 単一: 22\n" +
			"  - 範囲: 1-65535\n" +
			"  - 複数: 22,80,3306\n" +
			"プリセット:\n" +
			"  - main: 一般ポート\n" +
			"  - service: サービスポート\n" +
			"  - db: データベースポート\n" +
			"  - web: Webポート\n" +
			"  - all: 全ポート\n" +
			"例: -p main, -p 80,443, -p 1-1000",

		LangRU: "Укажите порты сканирования:\n" +
			"Формат:\n" +
			"  - Один: 22\n" +
			"  - Диапазон: 1-65535\n" +
			"  - Несколько: 22,80,3306\n" +
			"Предустановки:\n" +
			"  - main: Общие порты\n" +
			"  - service: Порты служб\n" +
			"  - db: Порты баз данных\n" +
			"  - web: Web порты\n" +
			"  - all: Все порты\n" +
			"Пример: -p main, -p 80,443, -p 1-1000",
	},
	"flag_scan_mode": {
		LangZH: "指定扫描模式:\n" +
			"预设模式:\n" +
			"  - All: 全量扫描\n" +
			"  - Basic: 基础扫描(Web/FTP/SSH等)\n" +
			"  - Database: 数据库扫描\n" +
			"  - Web: Web服务扫描\n" +
			"  - Service: 常见服务扫描\n" +
			"  - Vul: 漏洞扫描\n" +
			"  - Port: 端口扫描\n" +
			"  - ICMP: 存活探测\n" +
			"  - Local: 本地信息\n" +
			"单项扫描:\n" +
			"  - web/db: mysql,redis等\n" +
			"  - service: ftp,ssh等\n" +
			"  - vul: ms17010等",

		LangEN: "Specify scan mode:\n" +
			"Preset modes:\n" +
			"  - All: Full scan\n" +
			"  - Basic: Basic scan(Web/FTP/SSH)\n" +
			"  - Database: Database scan\n" +
			"  - Web: Web service scan\n" +
			"  - Service: Common service scan\n" +
			"  - Vul: Vulnerability scan\n" +
			"  - Port: Port scan\n" +
			"  - ICMP: Alive detection\n" +
			"  - Local: Local info\n" +
			"Single scan:\n" +
			"  - web/db: mysql,redis etc\n" +
			"  - service: ftp,ssh etc\n" +
			"  - vul: ms17010 etc",

		LangJA: "スキャンモードを指定:\n" +
			"プリセットモード:\n" +
			"  - All: フルスキャン\n" +
			"  - Basic: 基本スキャン(Web/FTP/SSH)\n" +
			"  - Database: データベーススキャン\n" +
			"  - Web: Webサービススキャン\n" +
			"  - Service: 一般サービススキャン\n" +
			"  - Vul: 脆弱性スキャン\n" +
			"  - Port: ポートスキャン\n" +
			"  - ICMP: 生存確認\n" +
			"  - Local: ローカル情報\n" +
			"単一スキャン:\n" +
			"  - web/db: mysql,redis など\n" +
			"  - service: ftp,ssh など\n" +
			"  - vul: ms17010 など",

		LangRU: "Укажите режим сканирования:\n" +
			"Предустановки:\n" +
			"  - All: Полное сканирование\n" +
			"  - Basic: Базовое сканирование(Web/FTP/SSH)\n" +
			"  - Database: Сканирование БД\n" +
			"  - Web: Веб-сервисы\n" +
			"  - Service: Общие службы\n" +
			"  - Vul: Уязвимости\n" +
			"  - Port: Порты\n" +
			"  - ICMP: Обнаружение\n" +
			"  - Local: Локальная информация\n" +
			"Одиночное сканирование:\n" +
			"  - web/db: mysql,redis и др\n" +
			"  - service: ftp,ssh и др\n" +
			"  - vul: ms17010 и др",
	},
	"flag_exclude_hosts": {
		LangZH: "排除指定主机范围,支持CIDR格式,如: 192.168.1.1/24",
		LangEN: "Exclude host ranges, supports CIDR format, e.g.: 192.168.1.1/24",
		LangJA: "除外ホスト範囲を指定、CIDR形式対応、例: 192.168.1.1/24",
		LangRU: "Исключить диапазоны хостов, поддерживает формат CIDR, например: 192.168.1.1/24",
	},

	"flag_add_users": {
		LangZH: "在默认用户列表基础上添加自定义用户名",
		LangEN: "Add custom usernames to default user list",
		LangJA: "デフォルトユーザーリストにカスタムユーザー名を追加",
		LangRU: "Добавить пользовательские имена к списку по умолчанию",
	},

	"flag_add_passwords": {
		LangZH: "在默认密码列表基础上添加自定义密码",
		LangEN: "Add custom passwords to default password list",
		LangJA: "デフォルトパスワードリストにカスタムパスワードを追加",
		LangRU: "Добавить пользовательские пароли к списку по умолчанию",
	},

	"flag_username": {
		LangZH: "指定单个用户名",
		LangEN: "Specify single username",
		LangJA: "単一ユーザー名を指定",
		LangRU: "Указать одно имя пользователя",
	},

	"flag_password": {
		LangZH: "指定单个密码",
		LangEN: "Specify single password",
		LangJA: "単一パスワードを指定",
		LangRU: "Указать один пароль",
	},

	"flag_domain": {
		LangZH: "指定域名(仅用于SMB协议)",
		LangEN: "Specify domain name (SMB protocol only)",
		LangJA: "ドメイン名を指定(SMBプロトコルのみ)",
		LangRU: "Указать доменное имя (только для протокола SMB)",
	},

	"flag_ssh_key": {
		LangZH: "指定SSH私钥文件路径(默认为id_rsa)",
		LangEN: "Specify SSH private key file path (default: id_rsa)",
		LangJA: "SSH秘密鍵ファイルパスを指定(デフォルト: id_rsa)",
		LangRU: "Указать путь к файлу приватного ключа SSH (по умолчанию: id_rsa)",
	},

	"flag_thread_num": {
		LangZH: "设置扫描线程数",
		LangEN: "Set number of scanning threads",
		LangJA: "スキャンスレッド数を設定",
		LangRU: "Установить количество потоков сканирования",
	},

	"flag_timeout": {
		LangZH: "设置连接超时时间(单位:秒)",
		LangEN: "Set connection timeout (in seconds)",
		LangJA: "接続タイムアウトを設定(秒単位)",
		LangRU: "Установить таймаут соединения (в секундах)",
	},

	"flag_live_top": {
		LangZH: "仅显示指定数量的存活主机",
		LangEN: "Show only specified number of alive hosts",
		LangJA: "指定した数の生存ホストのみを表示",
		LangRU: "Показать только указанное количество активных хостов",
	},

	"flag_disable_ping": {
		LangZH: "禁用主机存活探测",
		LangEN: "Disable host alive detection",
		LangJA: "ホスト生存確認を無効化",
		LangRU: "Отключить обнаружение активных хостов",
	},

	"flag_use_ping": {
		LangZH: "使用系统ping命令替代ICMP探测",
		LangEN: "Use system ping command instead of ICMP probe",
		LangJA: "ICMPプローブの代わりにシステムpingコマンドを使用",
		LangRU: "Использовать системную команду ping вместо ICMP-зондирования",
	},

	"flag_command": {
		LangZH: "指定要执行的系统命令(支持ssh和wmiexec)",
		LangEN: "Specify system command to execute (supports ssh and wmiexec)",
		LangJA: "実行するシステムコマンドを指定(sshとwmiexecをサポート)",
		LangRU: "Указать системную команду для выполнения (поддерживает ssh и wmiexec)",
	},

	"flag_skip_fingerprint": {
		LangZH: "跳过端口指纹识别",
		LangEN: "Skip port fingerprint identification",
		LangJA: "ポートフィンガープリント識別をスキップ",
		LangRU: "Пропустить идентификацию отпечатков портов",
	},

	"flag_hosts_file": {
		LangZH: "从文件中读取目标主机列表",
		LangEN: "Read target host list from file",
		LangJA: "ファイルからターゲットホストリストを読み込む",
		LangRU: "Чтение списка целевых хостов из файла",
	},

	"flag_users_file": {
		LangZH: "从文件中读取用户名字典",
		LangEN: "Read username dictionary from file",
		LangJA: "ファイルからユーザー名辞書を読み込む",
		LangRU: "Чтение словаря имен пользователей из файла",
	},

	"flag_passwords_file": {
		LangZH: "从文件中读取密码字典",
		LangEN: "Read password dictionary from file",
		LangJA: "ファイルからパスワード辞書を読み込む",
		LangRU: "Чтение словаря паролей из файла",
	},

	"flag_hash_file": {
		LangZH: "从文件中读取Hash字典",
		LangEN: "Read hash dictionary from file",
		LangJA: "ファイルからハッシュ辞書を読み込む",
		LangRU: "Чтение словаря хэшей из файла",
	},

	"flag_ports_file": {
		LangZH: "从文件中读取端口列表",
		LangEN: "Read port list from file",
		LangJA: "ファイルからポートリストを読み込む",
		LangRU: "Чтение списка портов из файла",
	},

	"flag_target_url": {
		LangZH: "指定目标URL",
		LangEN: "Specify target URL",
		LangJA: "ターゲットURLを指定",
		LangRU: "Указать целевой URL",
	},

	"flag_urls_file": {
		LangZH: "从文件中读取URL列表",
		LangEN: "Read URL list from file",
		LangJA: "ファイルからURLリストを読み込む",
		LangRU: "Чтение списка URL из файла",
	},

	"flag_cookie": {
		LangZH: "设置HTTP请求Cookie",
		LangEN: "Set HTTP request cookie",
		LangJA: "HTTPリクエストのCookieを設定",
		LangRU: "Установить cookie HTTP-запроса",
	},

	"flag_web_timeout": {
		LangZH: "设置Web请求超时时间(单位:秒)",
		LangEN: "Set Web request timeout (in seconds)",
		LangJA: "Webリクエストタイムアウトを設定(秒単位)",
		LangRU: "Установить таймаут веб-запроса (в секундах)",
	},

	"flag_http_proxy": {
		LangZH: "设置HTTP代理服务器",
		LangEN: "Set HTTP proxy server",
		LangJA: "HTTPプロキシサーバーを設定",
		LangRU: "Установить HTTP прокси-сервер",
	},

	"flag_socks5_proxy": {
		LangZH: "设置Socks5代理(用于TCP连接,将影响超时设置)",
		LangEN: "Set Socks5 proxy (for TCP connections, will affect timeout settings)",
		LangJA: "Socks5プロキシを設定(TCP接続用、タイムアウト設定に影響します)",
		LangRU: "Установить Socks5 прокси (для TCP соединений, влияет на настройки таймаута)",
	},
	"flag_local_mode": {
		LangZH: "启用本地信息收集模式",
		LangEN: "Enable local information gathering mode",
		LangJA: "ローカル情報収集モードを有効化",
		LangRU: "Включить режим сбора локальной информации",
	},

	// POC配置相关
	"flag_poc_path": {
		LangZH: "指定自定义POC文件路径",
		LangEN: "Specify custom POC file path",
		LangJA: "カスタムPOCファイルパスを指定",
		LangRU: "Указать путь к пользовательскому файлу POC",
	},

	"flag_poc_name": {
		LangZH: "指定要使用的POC名称,如: -pocname weblogic",
		LangEN: "Specify POC name to use, e.g.: -pocname weblogic",
		LangJA: "使用するPOC名を指定、例: -pocname weblogic",
		LangRU: "Указать имя используемого POC, например: -pocname weblogic",
	},

	"flag_poc_full": {
		LangZH: "启用完整POC扫描(如测试shiro全部100个key)",
		LangEN: "Enable full POC scan (e.g. test all 100 shiro keys)",
		LangJA: "完全POCスキャンを有効化(例: shiroの全100キーをテスト)",
		LangRU: "Включить полное POC-сканирование (например, тест всех 100 ключей shiro)",
	},

	"flag_dns_log": {
		LangZH: "启用dnslog进行漏洞验证",
		LangEN: "Enable dnslog for vulnerability verification",
		LangJA: "脆弱性検証にdnslogを有効化",
		LangRU: "Включить dnslog для проверки уязвимостей",
	},

	"flag_poc_num": {
		LangZH: "设置POC扫描并发数",
		LangEN: "Set POC scan concurrency",
		LangJA: "POCスキャンの同時実行数を設定",
		LangRU: "Установить параллельность POC-сканирования",
	},

	// Redis配置相关
	"flag_redis_file": {
		LangZH: "指定Redis写入的SSH公钥文件",
		LangEN: "Specify SSH public key file for Redis write",
		LangJA: "Redis書き込み用のSSH公開鍵ファイルを指定",
		LangRU: "Указать файл публичного ключа SSH для записи Redis",
	},

	"flag_redis_shell": {
		LangZH: "指定Redis写入的计划任务内容",
		LangEN: "Specify cron task content for Redis write",
		LangJA: "Redis書き込み用のcronタスク内容を指定",
		LangRU: "Указать содержимое cron-задачи для записи Redis",
	},

	"flag_disable_redis": {
		LangZH: "禁用Redis安全检测",
		LangEN: "Disable Redis security detection",
		LangJA: "Redisセキュリティ検出を無効化",
		LangRU: "Отключить обнаружение безопасности Redis",
	},
	// 暴力破解配置
	"flag_disable_brute": {
		LangZH: "禁用密码暴力破解",
		LangEN: "Disable password brute force",
		LangJA: "パスワードブルートフォースを無効化",
		LangRU: "Отключить перебор паролей",
	},

	"flag_max_retries": {
		LangZH: "设置最大重试次数",
		LangEN: "Set maximum retry attempts",
		LangJA: "最大再試行回数を設定",
		LangRU: "Установить максимальное количество попыток",
	},

	// 其他配置
	"flag_remote_path": {
		LangZH: "指定FCG/SMB远程文件路径",
		LangEN: "Specify FCG/SMB remote file path",
		LangJA: "FCG/SMBリモートファイルパスを指定",
		LangRU: "Указать удаленный путь к файлу FCG/SMB",
	},

	"flag_hash_value": {
		LangZH: "指定要破解的Hash值",
		LangEN: "Specify hash value to crack",
		LangJA: "クラックするハッシュ値を指定",
		LangRU: "Указать хэш-значение для взлома",
	},

	"flag_shellcode": {
		LangZH: "指定MS17漏洞利用的shellcode",
		LangEN: "Specify shellcode for MS17 exploit",
		LangJA: "MS17エクスプロイト用のシェルコードを指定",
		LangRU: "Указать шеллкод для эксплойта MS17",
	},

	"flag_enable_wmi": {
		LangZH: "启用WMI协议扫描",
		LangEN: "Enable WMI protocol scan",
		LangJA: "WMIプロトコルスキャンを有効化",
		LangRU: "Включить сканирование протокола WMI",
	},

	// 输出配置
	"flag_output_file": {
		LangZH: "指定结果输出文件名",
		LangEN: "Specify output result filename",
		LangJA: "結果出力ファイル名を指定",
		LangRU: "Указать имя файла для вывода результатов",
	},

	"flag_output_format": {
		LangZH: "指定输出格式 (txt/json/csv)",
		LangEN: "Specify output format (txt/json/csv)",
		LangJA: "出力形式を指定 (txt/json/csv)",
		LangRU: "Указать формат вывода (txt/json/csv)",
	},

	"flag_disable_save": {
		LangZH: "禁止保存扫描结果",
		LangEN: "Disable saving scan results",
		LangJA: "スキャン結果の保存を無効化",
		LangRU: "Отключить сохранение результатов сканирования",
	},

	"flag_silent_mode": {
		LangZH: "启用静默扫描模式(减少屏幕输出)",
		LangEN: "Enable silent scan mode (reduce screen output)",
		LangJA: "サイレントスキャンモードを有効化(画面出力を減らす)",
		LangRU: "Включить тихий режим сканирования (уменьшить вывод на экран)",
	},

	"flag_no_color": {
		LangZH: "禁用彩色输出显示",
		LangEN: "Disable colored output display",
		LangJA: "カラー出力表示を無効化",
		LangRU: "Отключить цветной вывод",
	},

	"flag_json_format": {
		LangZH: "以JSON格式输出结果",
		LangEN: "Output results in JSON format",
		LangJA: "結果をJSON形式で出力",
		LangRU: "Вывести результаты в формате JSON",
	},

	"flag_log_level": {
		LangZH: "日志输出级别(ALL/SUCCESS/ERROR/INFO/DEBUG)",
		LangEN: "Log output level (ALL/SUCCESS/ERROR/INFO/DEBUG)",
		LangJA: "ログ出力レベル(ALL/SUCCESS/ERROR/INFO/DEBUG)",
		LangRU: "Уровень вывода журнала (ALL/SUCCESS/ERROR/INFO/DEBUG)",
	},

	"flag_show_progress": {
		LangZH: "开启进度条显示",
		LangEN: "Enable progress bar display",
		LangJA: "プログレスバー表示を有効化",
		LangRU: "Включить отображение индикатора выполнения",
	},
	"no_username_specified": {
		LangZH: "加载用户名: %d 个",
		LangEN: "Loaded usernames: %d",
		LangJA: "ユーザー名を読み込み: %d 個",
		LangRU: "Загружено имен пользователей: %d",
	},
	"load_usernames_from_file": {
		LangZH: "从文件加载用户名: %d 个",
		LangEN: "Loaded usernames from file: %d",
		LangJA: "ファイルからユーザー名を読み込み: %d 個",
		LangRU: "Загружено имен пользователей из файла: %d",
	},
	"total_usernames": {
		LangZH: "用户名总数: %d 个",
		LangEN: "Total usernames: %d",
		LangJA: "ユーザー名の総数: %d 個",
		LangRU: "Всего имен пользователей: %d",
	},
	"load_passwords": {
		LangZH: "加载密码: %d 个",
		LangEN: "Loaded passwords: %d",
		LangJA: "パスワードを読み込み: %d 個",
		LangRU: "Загружено паролей: %d",
	},
	"load_passwords_from_file": {
		LangZH: "从文件加载密码: %d 个",
		LangEN: "Loaded passwords from file: %d",
		LangJA: "ファイルからパスワードを読み込み: %d 個",
		LangRU: "Загружено паролей из файла: %d",
	},
	"invalid_hash": {
		LangZH: "无效的哈希值: %s (长度!=32)",
		LangEN: "Invalid hash: %s (length!=32)",
		LangJA: "無効なハッシュ値: %s (長さ!=32)",
		LangRU: "Недопустимый хэш: %s (длина!=32)",
	},
	"load_valid_hashes": {
		LangZH: "加载有效哈希值: %d 个",
		LangEN: "Loaded valid hashes: %d",
		LangJA: "有効なハッシュ値を読み込み: %d 個",
		LangRU: "Загружено допустимых хэшей: %d",
	},
	"load_urls": {
		LangZH: "加载URL: %d 个",
		LangEN: "Loaded URLs: %d",
		LangJA: "URLを読み込み: %d 個",
		LangRU: "Загружено URL: %d",
	},
	"load_urls_from_file": {
		LangZH: "从文件加载URL: %d 个",
		LangEN: "Loaded URLs from file: %d",
		LangJA: "ファイルからURLを読み込み: %d 個",
		LangRU: "Загружено URL из файла: %d",
	},
	"load_hosts_from_file": {
		LangZH: "从文件加载主机: %d 个",
		LangEN: "Loaded hosts from file: %d",
		LangJA: "ファイルからホストを読み込み: %d 個",
		LangRU: "Загружено хостов из файла: %d",
	},
	"load_ports_from_file": {
		LangZH: "从文件加载端口配置",
		LangEN: "Loaded ports from file",
		LangJA: "ファイルからポート設定を読み込み",
		LangRU: "Загружены порты из файла",
	},
	"open_file_failed": {
		LangZH: "打开文件失败 %s: %v",
		LangEN: "Failed to open file %s: %v",
		LangJA: "ファイルを開けませんでした %s: %v",
		LangRU: "Не удалось открыть файл %s: %v",
	},
	"read_file_failed": {
		LangZH: "读取文件错误 %s: %v",
		LangEN: "Error reading file %s: %v",
		LangJA: "ファイル読み込みエラー %s: %v",
		LangRU: "Ошибка чтения файла %s: %v",
	},
	"read_file_success": {
		LangZH: "读取文件成功 %s: %d 行",
		LangEN: "Successfully read file %s: %d lines",
		LangJA: "ファイル読み込み成功 %s: %d 行",
		LangRU: "Успешно прочитан файл %s: %d строк",
	},
	"specify_scan_params": {
		LangZH: "请指定扫描参数",
		LangEN: "Please specify scan parameters",
		LangJA: "スキャンパラメータを指定してください",
		LangRU: "Пожалуйста, укажите параметры сканирования",
	},
	"params_conflict": {
		LangZH: "参数 -h、-u、-local 不能同时使用",
		LangEN: "Parameters -h, -u, -local cannot be used simultaneously",
		LangJA: "パラメータ -h、-u、-local は同時に使用できません",
		LangRU: "Параметры -h, -u, -local нельзя использовать одновременно",
	},
	"brute_threads": {
		LangZH: "暴力破解线程数: %d",
		LangEN: "Brute force threads: %d",
		LangJA: "ブルートフォーススレッド数: %d",
		LangRU: "Потоков для брутфорса: %d",
	},
	"extra_ports": {
		LangZH: "额外端口: %s",
		LangEN: "Extra ports: %s",
		LangJA: "追加ポート: %s",
		LangRU: "Дополнительные порты: %s",
	},
	"extra_usernames": {
		LangZH: "额外用户名: %s",
		LangEN: "Extra usernames: %s",
		LangJA: "追加ユーザー名: %s",
		LangRU: "Дополнительные имена пользователей: %s",
	},
	"extra_passwords": {
		LangZH: "额外密码: %s",
		LangEN: "Extra passwords: %s",
		LangJA: "追加パスワード: %s",
		LangRU: "Дополнительные пароли: %s",
	},
	"socks5_proxy": {
		LangZH: "Socks5代理: %s",
		LangEN: "Socks5 proxy: %s",
		LangJA: "Socks5プロキシ: %s",
		LangRU: "Socks5 прокси: %s",
	},
	"socks5_proxy_error": {
		LangZH: "Socks5代理格式错误: %v",
		LangEN: "Invalid Socks5 proxy format: %v",
		LangJA: "Socks5プロキシフォーマットエラー: %v",
		LangRU: "Неверный формат Socks5 прокси: %v",
	},
	"http_proxy": {
		LangZH: "HTTP代理: %s",
		LangEN: "HTTP proxy: %s",
		LangJA: "HTTPプロキシ: %s",
		LangRU: "HTTP прокси: %s",
	},
	"unsupported_proxy": {
		LangZH: "不支持的代理类型",
		LangEN: "Unsupported proxy type",
		LangJA: "サポートされていないプロキシタイプ",
		LangRU: "Неподдерживаемый тип прокси",
	},
	"proxy_format_error": {
		LangZH: "代理格式错误: %v",
		LangEN: "Invalid proxy format: %v",
		LangJA: "プロキシフォーマットエラー: %v",
		LangRU: "Неверный формат прокси: %v",
	},
	"hash_length_error": {
		LangZH: "Hash长度必须为32位",
		LangEN: "Hash length must be 32 bits",
		LangJA: "ハッシュ長は32ビットでなければなりません",
		LangRU: "Длина хэша должна быть 32 бита",
	},
	"hash_decode_failed": {
		LangZH: "Hash解码失败: %s",
		LangEN: "Hash decode failed: %s",
		LangJA: "ハッシュのデコードに失敗: %s",
		LangRU: "Не удалось декодировать хэш: %s",
	},
	"parse_ip_error": {
		LangZH: "主机解析错误\n" +
			"支持的格式: \n" +
			"192.168.1.1                   (单个IP)\n" +
			"192.168.1.1/8                 (8位子网)\n" +
			"192.168.1.1/16                (16位子网)\n" +
			"192.168.1.1/24                (24位子网)\n" +
			"192.168.1.1,192.168.1.2       (IP列表)\n" +
			"192.168.1.1-192.168.255.255   (IP范围)\n" +
			"192.168.1.1-255               (最后一位简写范围)",

		LangEN: "Host parsing error\n" +
			"Supported formats: \n" +
			"192.168.1.1                   (Single IP)\n" +
			"192.168.1.1/8                 (8-bit subnet)\n" +
			"192.168.1.1/16                (16-bit subnet)\n" +
			"192.168.1.1/24                (24-bit subnet)\n" +
			"192.168.1.1,192.168.1.2       (IP list)\n" +
			"192.168.1.1-192.168.255.255   (IP range)\n" +
			"192.168.1.1-255               (Last octet range)",

		LangJA: "ホスト解析エラー\n" +
			"サポートされる形式: \n" +
			"192.168.1.1                   (単一IP)\n" +
			"192.168.1.1/8                 (8ビットサブネット)\n" +
			"192.168.1.1/16                (16ビットサブネット)\n" +
			"192.168.1.1/24                (24ビットサブネット)\n" +
			"192.168.1.1,192.168.1.2       (IPリスト)\n" +
			"192.168.1.1-192.168.255.255   (IP範囲)\n" +
			"192.168.1.1-255               (最後のオクテット範囲)",

		LangRU: "Ошибка разбора хоста\n" +
			"Поддерживаемые форматы: \n" +
			"192.168.1.1                   (Одиночный IP)\n" +
			"192.168.1.1/8                 (8-битная подсеть)\n" +
			"192.168.1.1/16                (16-битная подсеть)\n" +
			"192.168.1.1/24                (24-битная подсеть)\n" +
			"192.168.1.1,192.168.1.2       (Список IP)\n" +
			"192.168.1.1-192.168.255.255   (Диапазон IP)\n" +
			"192.168.1.1-255               (Диапазон последнего октета)",
	},
	"host_port_parsed": {
		LangZH: "已解析主机端口组合,端口设置为: %s",
		LangEN: "Host port combination parsed, port set to: %s",
		LangJA: "ホストポートの組み合わせを解析し、ポートを設定: %s",
		LangRU: "Комбинация хост-порт разобрана, порт установлен на: %s",
	},
	"read_host_file_failed": {
		LangZH: "读取主机文件失败: %v",
		LangEN: "Failed to read host file: %v",
		LangJA: "ホストファイルの読み取りに失敗: %v",
		LangRU: "Не удалось прочитать файл хостов: %v",
	},
	"extra_hosts_loaded": {
		LangZH: "从文件加载额外主机: %d 个",
		LangEN: "Loaded extra hosts from file: %d",
		LangJA: "ファイルから追加ホストを読み込み: %d",
		LangRU: "Загружено дополнительных хостов из файла: %d",
	},
	"hosts_excluded": {
		LangZH: "已排除指定主机: %d 个",
		LangEN: "Excluded specified hosts: %d",
		LangJA: "指定されたホストを除外: %d",
		LangRU: "Исключено указанных хостов: %d",
	},
	"final_valid_hosts": {
		LangZH: "最终有效主机数量: %d",
		LangEN: "Final valid host count: %d",
		LangJA: "最終的な有効ホスト数: %d",
		LangRU: "Итоговое количество действительных хостов: %d",
	},
	"invalid_ip_format": {
		LangZH: "无效的IP格式: %s",
		LangEN: "Invalid IP format: %s",
		LangJA: "無効なIP形式: %s",
		LangRU: "Неверный формат IP: %s",
	},
	"cidr_parse_failed": {
		LangZH: "CIDR格式解析失败: %s, %v",
		LangEN: "CIDR format parse failed: %s, %v",
		LangJA: "CIDR形式の解析に失敗: %s, %v",
		LangRU: "Ошибка разбора формата CIDR: %s, %v",
	},
	"parse_cidr_to_range": {
		LangZH: "解析CIDR %s -> IP范围 %s",
		LangEN: "Parse CIDR %s -> IP range %s",
		LangJA: "CIDR %s -> IP範囲 %s を解析",
		LangRU: "Разбор CIDR %s -> диапазон IP %s",
	},
	"ip_range_format_error": {
		LangZH: "IP范围格式错误: %s",
		LangEN: "IP range format error: %s",
		LangJA: "IP範囲形式エラー: %s",
		LangRU: "Ошибка формата диапазона IP: %s",
	},
	"invalid_ip_range": {
		LangZH: "IP范围无效: %d-%d",
		LangEN: "Invalid IP range: %d-%d",
		LangJA: "無効なIP範囲: %d-%d",
		LangRU: "Недопустимый диапазон IP: %d-%d",
	},
	"generate_ip_range": {
		LangZH: "生成IP范围: %s.%d - %s.%d",
		LangEN: "Generate IP range: %s.%d - %s.%d",
		LangJA: "IP範囲を生成: %s.%d - %s.%d",
		LangRU: "Создание диапазона IP: %s.%d - %s.%d",
	},
	"ip_format_error": {
		LangZH: "IP格式错误: %s",
		LangEN: "IP format error: %s",
		LangJA: "IP形式エラー: %s",
		LangRU: "Ошибка формата IP: %s",
	},
	"cidr_range": {
		LangZH: "CIDR范围: %s",
		LangEN: "CIDR range: %s",
		LangJA: "CIDR範囲: %s",
		LangRU: "Диапазон CIDR: %s",
	},
	"invalid_port": {
		LangZH: "忽略无效端口: %s",
		LangEN: "Ignore invalid port: %s",
		LangJA: "無効なポートを無視: %s",
		LangRU: "Игнорирование недопустимого порта: %s",
	},
	"parse_ip_port": {
		LangZH: "解析IP端口组合: %s",
		LangEN: "Parse IP port combination: %s",
		LangJA: "IPポートの組み合わせを解析: %s",
		LangRU: "Разбор комбинации IP-порт: %s",
	},
	"parse_ip_address": {
		LangZH: "解析IP地址: %s",
		LangEN: "Parse IP address: %s",
		LangJA: "IPアドレスを解析: %s",
		LangRU: "Разбор IP-адреса: %s",
	},
	"read_file_error": {
		LangZH: "读取文件错误: %v",
		LangEN: "Read file error: %v",
		LangJA: "ファイル読み取りエラー: %v",
		LangRU: "Ошибка чтения файла: %v",
	},
	"file_parse_complete": {
		LangZH: "从文件解析完成: %d 个IP地址",
		LangEN: "File parsing complete: %d IP addresses",
		LangJA: "ファイルの解析が完了: %d 個のIPアドレス",
		LangRU: "Разбор файла завершен: %d IP-адресов",
	},
	"parse_subnet": {
		LangZH: "解析网段: %s.0.0.0/8",
		LangEN: "Parse subnet: %s.0.0.0/8",
		LangJA: "サブネットを解析: %s.0.0.0/8",
		LangRU: "Разбор подсети: %s.0.0.0/8",
	},
	"sample_ip_generated": {
		LangZH: "生成采样IP: %d 个",
		LangEN: "Generated sample IPs: %d",
		LangJA: "サンプルIPを生成: %d 個",
		LangRU: "Сгенерировано примеров IP: %d",
	},
	"port_range_format_error": {
		LangZH: "端口范围格式错误: %s",
		LangEN: "Invalid port range format: %s",
		LangJA: "ポート範囲フォーマットエラー: %s",
		LangRU: "Неверный формат диапазона портов: %s",
	},
	"ignore_invalid_port": {
		LangZH: "忽略无效端口: %d",
		LangEN: "Ignore invalid port: %d",
		LangJA: "無効なポートを無視: %d",
		LangRU: "Игнорирование недопустимого порта: %d",
	},
	"valid_port_count": {
		LangZH: "有效端口数量: %d",
		LangEN: "Valid port count: %d",
		LangJA: "有効なポート数: %d",
		LangRU: "Количество действительных портов: %d",
	},
	"parse_scan_mode": {
		LangZH: "解析扫描模式: %s",
		LangEN: "Parse scan mode: %s",
		LangJA: "スキャンモードを解析: %s",
		LangRU: "Разбор режима сканирования: %s",
	},
	"using_preset_mode": {
		LangZH: "使用预设模式: %s",
		LangEN: "Using preset mode: %s",
		LangJA: "プリセットモードを使用: %s",
		LangRU: "Использование предустановленного режима: %s",
	},
	"using_preset_mode_plugins": {
		LangZH: "使用预设模式: %s, 包含插件: %v",
		LangEN: "Using preset mode: %s, included plugins: %v",
		LangJA: "プリセットモードを使用: %s, 含まれるプラグイン: %v",
		LangRU: "Использование предустановленного режима: %s, включенные плагины: %v",
	},
	"using_single_plugin": {
		LangZH: "使用单个插件: %s",
		LangEN: "Using single plugin: %s",
		LangJA: "単一のプラグインを使用: %s",
		LangRU: "Использование одного плагина: %s",
	},
	"using_default_mode": {
		LangZH: "未识别的模式，使用默认模式: %s",
		LangEN: "Unrecognized mode, using default mode: %s",
		LangJA: "認識できないモード、デフォルトモードを使用: %s",
		LangRU: "Нераспознанный режим, использование режима по умолчанию: %s",
	},
	"included_plugins": {
		LangZH: "包含插件: %v",
		LangEN: "Included plugins: %v",
		LangJA: "含まれるプラグイン: %v",
		LangRU: "Включенные плагины: %v",
	},
	"tcp_conn_failed": {
		LangZH: "建立TCP连接失败: %v",
		LangEN: "Failed to establish TCP connection: %v",
		LangJA: "TCP接続の確立に失敗しました: %v",
		LangRU: "Не удалось установить TCP-соединение: %v",
	},
	"socks5_create_failed": {
		LangZH: "创建Socks5代理失败: %v",
		LangEN: "Failed to create Socks5 proxy: %v",
		LangJA: "Socks5プロキシの作成に失敗しました: %v",
		LangRU: "Не удалось создать прокси Socks5: %v",
	},
	"socks5_conn_failed": {
		LangZH: "通过Socks5建立连接失败: %v",
		LangEN: "Failed to establish connection through Socks5: %v",
		LangJA: "Socks5経由での接続確立に失敗しました: %v",
		LangRU: "Не удалось установить соединение через Socks5: %v",
	},
	"socks5_parse_failed": {
		LangZH: "解析Socks5代理地址失败: %v",
		LangEN: "Failed to parse Socks5 proxy address: %v",
		LangJA: "Socks5プロキシアドレスの解析に失敗しました: %v",
		LangRU: "Не удалось разобрать адрес прокси Socks5: %v",
	},
	"socks5_only": {
		LangZH: "仅支持socks5代理",
		LangEN: "Only socks5 proxy is supported",
		LangJA: "socks5プロキシのみサポートされています",
		LangRU: "Поддерживается только прокси socks5",
	},
	"flag_language": {
		LangZH: "指定界面语言 (zh:中文, en:英文, ja:日文, ru:俄文)",
		LangEN: "Specify interface language (zh:Chinese, en:English, ja:Japanese, ru:Russian)",
		LangJA: "インターフェース言語を指定 (zh:中国語, en:英語, ja:日本語, ru:ロシア語)",
		LangRU: "Указать язык интерфейса (zh:Китайский, en:Английский, ja:Японский, ru:Русский)",
	},
	"icmp_listen_failed": {
		LangZH: "ICMP监听失败: %v",
		LangEN: "ICMP listen failed: %v",
		LangJA: "ICMPリッスンに失敗: %v",
		LangRU: "Ошибка прослушивания ICMP: %v",
	},
	"trying_no_listen_icmp": {
		LangZH: "正在尝试无监听ICMP探测...",
		LangEN: "Trying ICMP probe without listening...",
		LangJA: "リッスンなしICMP探知を試みています...",
		LangRU: "Пробуем ICMP-зондирование без прослушивания...",
	},
	"icmp_connect_failed": {
		LangZH: "ICMP连接失败: %v",
		LangEN: "ICMP connection failed: %v",
		LangJA: "ICMP接続に失敗: %v",
		LangRU: "Ошибка подключения ICMP: %v",
	},
	"insufficient_privileges": {
		LangZH: "当前用户权限不足,无法发送ICMP包",
		LangEN: "Insufficient privileges to send ICMP packets",
		LangJA: "ICMPパケットを送信する権限が不足しています",
		LangRU: "Недостаточно прав для отправки ICMP-пакетов",
	},
	"switching_to_ping": {
		LangZH: "切换为PING方式探测...",
		LangEN: "Switching to PING probe...",
		LangJA: "PING探知に切り替えています...",
		LangRU: "Переключение на PING-зондирование...",
	},
	"subnet_16_alive": {
		LangZH: "%s.0.0/16 存活主机数: %d",
		LangEN: "%s.0.0/16 alive hosts: %d",
		LangJA: "%s.0.0/16 生存ホスト数: %d",
		LangRU: "%s.0.0/16 живых хостов: %d",
	},
	"subnet_24_alive": {
		LangZH: "%s.0/24 存活主机数: %d",
		LangEN: "%s.0/24 alive hosts: %d",
		LangJA: "%s.0/24 生存ホスト数: %d",
		LangRU: "%s.0/24 живых хостов: %d",
	},
	"target_alive": {
		LangZH: "目标 %-15s 存活 (%s)",
		LangEN: "Target %-15s is alive (%s)",
		LangJA: "ターゲット %-15s は生存 (%s)",
		LangRU: "Цель %-15s жива (%s)",
	},
}

// 当前语言设置
var currentLang = LangZH

func SetLanguage() {
	// 使用flag设置的语言
	switch strings.ToLower(Language) {
	case LangZH, LangEN, LangJA, LangRU:
		currentLang = strings.ToLower(Language)
	default:
		currentLang = LangEN // 不支持的语言默认使用英文
	}
}

// GetText 获取指定key的当前语言文本
func GetText(key string, args ...interface{}) string {
	if texts, ok := i18nMap[key]; ok {
		if text, ok := texts[currentLang]; ok {
			if len(args) > 0 {
				return fmt.Sprintf(text, args...)
			}
			return text
		}
	}
	return key
}
