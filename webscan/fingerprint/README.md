# fscan 增强指纹库

## 概述

当前版本并行使用基础规则、[FingerprintHub](https://github.com/0x727/FingerprintHub)
和 [ProjectDiscovery WappalyzerGo](https://github.com/projectdiscovery/wappalyzergo)
进行 Web 指纹识别。Wappalyzer 数据固定为 `v0.2.93`，覆盖中间件、框架、CMS、
前端组件、分析平台和托管服务等 7,553 种技术。

## 指纹库规模

### 基础指纹库 (原有)
- **正则规则**: 242条 (RuleDatas)
- **MD5指纹**: 30条 (Md5Datas)
- **特点**: 国内OA/WAF为主，轻量高效
- **文件**: `rules.go` (硬编码)

### 增强指纹库 (新增)
- **指纹数量**: 3,139条
- **来源**: FingerprintHub v4.0
- **特点**: 国内外主流应用，社区维护
- **文件**: `web_fingerprint_v4.json` (1.3MB)

### Wappalyzer 技术指纹库
- **技术数量**: 7,553条
- **来源**: ProjectDiscovery WappalyzerGo v0.2.93
- **特点**: HTTP Header、Cookie、HTML、Meta、Script URL及技术依赖推导
- **兼容性**: 完整覆盖对比程序使用的 WappalyzerGo v0.0.71（3,459条），并保留30种技术的40条旧版静态规则
- **限制**: 不运行浏览器或执行页面 JavaScript，因此纯运行时 JS/DOM 属性规则不会单独触发

### 总计
```
基础指纹:  272条
增强指纹:  3,139条
Wappalyzer: 7,553条
─────────────────
合计规则源: 10,964条
```

不同数据库存在交叉和别名，因此合计表示规则源规模，不表示互不重复的技术数量。

---

## 技术实现

### 架构设计

```
┌─────────────────────────────────────┐
│  fingerprint_scanner.go             │
│  InfoCheck() 统一入口                │
└─────────────────────────────────────┘
            │
            ├─> 基础指纹库
            │   ├─ matchByRegex()  (242条)
            │   └─ matchByMd5()     (30条)
            │
            └─> 增强指纹库
                └─ MatchEnhancedFingerprints() (3139条)
                    ├─ matchWords()    (关键词匹配)
                    ├─ matchRegex()    (正则匹配)
                    └─ matchFavicon()  (icon hash)
```

### 核心特性

#### 1. 多种matcher类型
```go
支持的matcher类型:
- word:     关键词匹配 (大小写可选)
- regex:    正则表达式匹配
- favicon:  图标hash匹配
```

#### 2. Condition逻辑
```go
- or:  任一条件满足即匹配 (默认)
- and: 所有条件都满足才匹配
```

#### 3. Part选择
```go
- body:    响应体匹配 (默认)
- header:  响应头匹配
```

#### 4. 性能优化
- **正则缓存**: 编译后的正则表达式缓存
- **Lazy加载**: 首次调用时才加载JSON
- **Embed内嵌**: 编译时打包,无需外部文件

---

## 使用示例

### 基本用法
```go
import "scanner/webscan/fingerprint"

// 自动加载并匹配
body := []byte("<html>...</html>")
headers := "Server: nginx/1.18.0"

// 计算 favicon hash（同时支持 mmh3 和 MD5 格式）
faviconData := []byte{...} // 从 /favicon.ico 下载的数据
favicon := fingerprint.CalculateFaviconHashes(faviconData)

matched := fingerprint.MatchEnhancedFingerprints(body, headers, favicon)
// 返回: ["nginx", "wordpress", ...]
```

### 指纹格式示例

**WordPress指纹**:
```json
{
  "id": "wordpress",
  "info": {
    "name": "wordpress",
    "tags": "detect,tech,wordpress"
  },
  "http": [{
    "matchers": [{
      "type": "word",
      "words": [
        "/wp-content/themes/",
        "/wp-includes/"
      ],
      "case-insensitive": true
    }]
  }]
}
```

**禅道OA指纹** (AND条件):
```json
{
  "id": "zentao",
  "http": [{
    "matchers": [{
      "type": "word",
      "words": [
        "/zentao/theme",
        "zentaosid"
      ],
      "condition": "and"
    }]
  }]
}
```

**Favicon Hash指纹**:
```json
{
  "id": "openemr",
  "http": [{
    "matchers": [{
      "type": "favicon",
      "hash": ["1971268439"]
    }]
  }]
}
```

---

## 验证结果

### 测试用例
```bash
$ go run test_enhanced_fingerprint.go

✅ 增强指纹库加载成功

测试1 - WordPress识别:
  匹配结果: [wordpress]
  ✅ WordPress指纹匹配成功

测试2 - Nginx识别:
  匹配结果: [nginx]
  ✅ Nginx指纹匹配成功

测试3 - 禅道OA识别:
  匹配结果: [zentao-system zentao]
  ✅ 禅道指纹匹配成功
```

---

## 文件说明

| 文件 | 大小 | 说明 |
|------|------|------|
| `web_fingerprint_v4.json` | 1.3MB | FingerprintHub指纹库 |
| `enhanced.go` | ~7KB | 增强指纹匹配引擎 |
| `rules.go` | ~150KB | 基础指纹库(原有) |
| `fingerprint_scanner.go` | ~3KB | 统一入口(修改) |

---

## 性能影响

### 编译后二进制
- **旧版本**: ~30MB
- **新版本**: ~57MB (+27MB)
- **原因**: embed了1.3MB JSON + 引擎代码

### 运行时性能
- **内存**: 首次加载 +2MB (JSON解析)
- **速度**: 正则缓存后无明显影响
- **并发**: 两套指纹库并行匹配

---

## 与原有指纹库的对比

| 维度 | 基础指纹库 | 增强指纹库 |
|------|-----------|-----------|
| **数量** | 272条 | 3,139条 |
| **来源** | 内置 | FingerprintHub |
| **格式** | Go代码 | JSON |
| **扩展性** | 需改代码 | 社区更新 |
| **覆盖范围** | 国内OA/WAF | 国内外全栈 |
| **Favicon** | ❌ | ✅ |
| **版本提取** | ❌ | ✅ (待实现) |
| **Condition** | 简单 | AND/OR |
| **Part** | 固定 | 可选 |

---

## 后续计划

### 已实现功能
- [x] Favicon自动下载和hash计算 ✅
- [x] 使用mmh3算法计算favicon hash ✅
- [x] 并发指纹匹配（~267μs/3000+规则）✅
- [x] Version extractor（通用版本提取）✅
- [x] 指纹优先级排序（favicon > regex > word）✅

### 待实现功能
- [ ] 支持加载外部JSON文件

### 潜在改进
- [ ] 支持更多matcher类型 (status, size, binary)
- [ ] 指纹库热更新机制
- [ ] 匹配结果包含CPE信息

---

## 参考资料

- [FingerprintHub GitHub](https://github.com/0x727/FingerprintHub)
- [Observer Ward](https://github.com/emo-crab/observer_ward)
- [Nuclei Templates](https://github.com/projectdiscovery/nuclei-templates)

---

## License

增强指纹库来自FingerprintHub项目,遵循其原始License。
