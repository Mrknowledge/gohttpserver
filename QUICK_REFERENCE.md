# 快速参考：SuperAdmin 权限系统

## 🎯 核心概念

通过 `superAdmin` 字段区分两类管理员：

```
普通管理员 (editAuth=true, superAdmin=false)
└─ ✅ 编辑 Auth Config
   ❌ 无法编辑 User Config

超级管理员 (delete=true, superAdmin=true)
└─ ✅ 编辑 Auth Config
   ✅ 编辑 User Config
```

## 🔧 配置方式

在 `.ghs.yml` 中添加 `superAdmin: true`：

```yaml
users:
  - email: admin@example.com
    token: token123
    delete: true
    superAdmin: true      # 👈 这一行决定了是否能编辑 User Config
```

## 🚀 立即可用的配置

### 最小化配置
```yaml
users:
  - admin@example.com: password

users:
  - email: admin@example.com
    token: admin_token
    show: true
    upload: true
    delete: true
    superAdmin: true
```

### 多用户配置
```yaml
users:
  - admin@example.com: admin_pwd
  - user1@example.com: user1_pwd
  - user2@example.com: user2_pwd

users:
  - email: admin@example.com
    token: admin_token
    delete: true
    superAdmin: true    # 超级管理员
    
  - email: user1@example.com
    token: user1_token
    delete: true
    superAdmin: false   # 普通管理员
    
  - email: user2@example.com
    token: user2_token
    delete: false
    superAdmin: false   # 普通用户
```

## 📱 前端显示

| 账户类型 | User Config 按钮 | Auth Config 按钮 |
|---------|-----------------|-----------------|
| 超级管理员 | ✅ 可见 | ✅ 可见 |
| 普通管理员 | ❌ 隐藏 | ✅ 可见 |
| 普通用户 | ❌ 隐藏 | ❌ 隐藏 |

## 🔐 权限检查流程

```
请求来到 → 验证登录 → 检查 `editAuth` / `delete` 权限 → 检查 superAdmin 权限
          (Validate)  (canDelete)        (canEditUserConfig)
                           ↓
                  是否访问 User Config？
                    /              \
                 是/              \否
                 ↓                 ↓
          需要 superAdmin=true   可以访问 Auth Config
                 ↓
          superAdmin=true? 
            /            \
          是/            \否
          ↓              ↓
      允许访问      返回 403
```

## 🛡️ 安全提示

1. **后端优先** - 前端按钮隐藏只是 UX，真正验证在后端
2. **无法绕过** - 直接调用 API 也会被拒绝
3. **多重验证** - User Config 需要同时满足 delete=true 和 superAdmin=true（Auth Config 的编辑由 `editAuth` 控制）

## ⚡ 常见场景

### 场景1：升级管理员
```yaml
# 原配置
- email: user@example.com
  delete: true
  
# 升级为超级管理员
- email: user@example.com
  delete: true
  superAdmin: true  # 添加这一行
```

### 场景2：降级管理员
```yaml
# 原配置
- email: user@example.com
  delete: true
  superAdmin: true
  
# 降级为普通管理员（不能编辑 User Config）
- email: user@example.com
  delete: true
  superAdmin: false  # 改为 false
```

### 场景3：创建只读用户
```yaml
- email: viewer@example.com
  token: viewer_token
  show: true
  upload: false
  delete: false
  superAdmin: false
```

## 📝 修改后需要重启吗？

**不需要！** 配置更改会立即生效（下次请求时读取新配置）

## ✅ 验证配置

使用对应账户登录后：

1. **超级管理员** → 应该看到两个按钮：User Config + Auth Config
2. **普通管理员** → 应该只看到：Auth Config
3. **普通用户** → 应该都看不到

## 🔍 API 端点

- **查看 User Config** - `GET ?op=conf&type=user`
- **保存 User Config** - `PUT ?op=conf&type=user&content=...`
- **查看 Auth Config** - `GET ?op=conf`
- **保存 Auth Config** - `PUT ?op=conf&content=...`

所有 User Config 操作都需要 `superAdmin: true`（且通常同时要求 `delete: true`）

---

**需要更多帮助？** 查看详细文档：
- `SUPERADMIN_SETUP.md` - 配置说明
- `IMPLEMENTATION_SUMMARY.md` - 技术细节
- `config-example.yml` - 配置示例
