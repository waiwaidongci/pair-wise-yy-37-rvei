# 空气污染源许可与合规检查

管理设施、排放口、治理设备、现场检查、整改和许可续期。

## 模块结构

- `app.py`：参数解析、依赖组装和HTTP服务启动。
- `src/domain.py`：数据结构、错误、状态和基础校验。
- `src/rules.py`：状态机、角色矩阵、优先级、期限和关闭不变量。
- `src/repository.py`：SQLite建表、事务、版本控制和审计链。
- `src/service.py`：权限检查、用例编排、并发控制和审计。
- `src/http_api.py`：JSON路由和统一错误响应。
- `src/audit.py`：UTC时间和SHA-256审计事件。
- `static/index.html`：最小演示页。
- `tests/`：完整流程、规则和失败测试。

## 初始化与启动

```bash
python3 app.py --db ./data.db --port 8314
```

默认端口为`8314`，首次启动自动建库。使用`X-Actor`和`X-Role`请求头传递身份。

## 主要接口

- `GET /health`
- `GET /api/items`
- `POST /api/items`（可选`equipment_id`或`equipment_ref`关联治理设备）
- `GET /api/items/{id}`
- `POST /api/items/{id}/records`
- `POST /api/items/{id}/records/{record_id}/close`，关闭检查或整改记录
- `GET /api/items/{id}/releases`，放行结论历史
- `POST /api/items/{id}/transition`，必须提交`expected_version`
- `GET /api/equipment`、`POST /api/equipment`
- `GET /api/deactivations`、`POST /api/deactivations`、`GET /api/deactivations/{id}`
- `GET /api/audit`

允许角色：applicant, inspector, compliance_manager, viewer。申报量超过许可量或检查发现高严重度问题时提高优先级；存在未关闭整改时不能批准。

## 停用影响交接

监管员（inspector、compliance_manager）选定设备和时段后提交`POST /api/deactivations`：

- 按设施归拢关联许可与未关闭整改，生成交接清单；
- 先冻结受影响许可（禁止流转）和待执行检查（禁止关闭），整改仍可关闭；
- 同一设备和时段重复提交沿用首次批次（幂等键去重），并发提交时先到者生效；
- 检查或整改记录新增、关闭后，关联放行结论自动失效并按当前记录重算；
- 批次先落库再写入影响，写入失败保留原批次（`pending`），重试沿用原批次编号。

## 测试

```bash
python3 -m unittest discover -s tests -v
```
