# SuperAdmin 权限系统实现总结

## 问题描述

之前的系统通过 `delete` 权限来判断是否展示 **Auth Config** 和 **User Config**，但这样无法区分两类账户：
- **普通管理员**：应该能编辑 Auth Config
- **超级管理员**：应该能编辑 User Config 和 Auth Config

## 解决方案

引入新的权限字段 `superAdmin`，实现细粒度的权限控制。

## 实现细节

### 1. 后端修改

#### 文件：`httpstaticserver.go`

**新增字段：**
- `UserControl` 结构体中添加 `SuperAdmin bool` 字段
- `AccessConf` 结构体中添加 `CanEditUserConfig bool` 字段（仅用于前端显示，不存储到 YAML）

**新增方法：**
- `canEditUserConfig(r *http.Request) bool` - 检查当前用户是否是超级管理员

**修改的方法：**
- `hConf()` - 添加 User Config 的权限检查
- `hRename()` - 在保存 User Config 时添加权限检查
- `hJSONList()` - 返回 `canEditUserConfig` 标志给前端

### 2. 前端修改

#### 文件：`assets/index.html`

修改了 **User Config** 按钮的显示条件：
- 旧逻辑：`v-show="auth.delete"`
- 新逻辑：`v-show="auth.canEditUserConfig"`

这样只有超级管理员才能看到 User Config 按钮。

#### 文件：`assets/js/index.js`

无需修改（前端逻辑已通过 HTML 的 `v-show` 条件完成）

### 3. 配置文件示例

在 `.ghs.yml` 中配置用户权限：

```yaml
users:
  # 普通管理员 - 可以编辑 Auth Config
  - email: admin@example.com
    token: admin_token
    show: true
    upload: true
    delete: true
    superAdmin: false

  # 超级管理员 - 可以编辑 Auth Config 和 User Config
  - email: superadmin@example.com
    token: super_token
    show: true
    upload: true
    delete: true
    superAdmin: true
```

## 权限矩阵

| 操作 | 需要权限 | 说明 |
|------|---------|------|
| 查看 Auth Config | `editAuth: true` | 普通管理员可访问 |
| 编辑 Auth Config | `editAuth: true` | 普通管理员可编辑 |
| 查看 User Config | `delete: true` + `superAdmin: true` | 仅超级管理员可访问 |
| 编辑 User Config | `delete: true` + `superAdmin: true` | 仅超级管理员可编辑 |

## 前后端交互流程

### 读取配置

```
前端请求 GET ?op=conf&type=user
        ↓
后端 hConf() 函数
        ↓
检查是否登录和验证 (Validate)
        ↓
检查是否有 delete 权限 (canDelete)
        ↓
检查是否是超级管理员 (canEditUserConfig)
        ↓
返回配置 (User Config 内容) 或 403 错误
```

### 保存配置

```
前端请求 PUT ?op=conf&type=user
        ↓
后端 hRename() 函数
        ↓
检查是否登录和验证 (Validate)
        ↓
检查是否有 delete 权限 (canDelete)
        ↓
检查是否是超级管理员 (canEditUserConfig)
        ↓
保存配置或返回 403 错误
```

## 安全特性

1. **后端验证优先**：所有权限检查都在后端进行，前端按钮隐藏只是 UX 优化
2. **多重验证**：User Config 需要同时满足 `delete: true` 和 `superAdmin: true`
3. **无权限返回 403**：即使前端按钮被绕过，直接调用 API 也会被拒绝

## 向后兼容性

- 现有配置无需修改，`superAdmin` 字段不存在时默认为 `false`
- 现有的普通管理员配置继续正常工作，不受影响
- 升级管理员权限只需在配置中添加 `superAdmin: true`

## 编译状态

✅ 代码已编译成功，无错误

## 文件变更清单

- ✅ `httpstaticserver.go` - 核心逻辑修改
- ✅ `assets/index.html` - 前端按钮显示逻辑修改
- ✅ `SUPERADMIN_SETUP.md` - 配置说明文档

## 测试建议

1. 使用普通管理员账户测试 - 应该能看到 Auth Config 按钮，但看不到 User Config 按钮
2. 使用超级管理员账户测试 - 应该能同时看到 Auth Config 和 User Config 按钮
3. 尝试直接调用 API 绕过前端 - 后端应该返回 403 错误

## 下一步

如果需要进一步增强权限系统：

1. 添加更多权限细分（如 `canEditAuth`、`canViewLog` 等）
2. 添加权限审计日志
3. 实现权限生命周期管理（过期时间等）
4. 创建权限模板/预设

