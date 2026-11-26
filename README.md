# sec3-abac-policy

策略里写的是部门等于财务才能看报表，结果写成部门前缀匹配，整个集团都能看：属性比较必须按类型而不是字符串；集合属性必须按成员判定；缺失属性必须导致拒绝而不是放行；条件组合必须短路求值；数值比较必须按数值；批量求值各请求独立。不变量：缺失任何必需属性必然拒绝；同一请求两次求值结果相同。

## 策略结构

策略是字典，包含 rules、combine、required_attributes 三个字段。rules 是规则列表，每条规则有 id、effect、condition；effect 取 allow 或 deny；condition 可以是 all、any、not 组合，也可以是 attr、op、value 形式。op 支持 eq、ne、in、not_in、has、has_any、prefix、gt、gte、lt、lte。required_attributes 列出策略依赖的属性名。

## 接口约定

parse_policy 返回规范化策略，保留规则顺序与结论，并统一条件结构。resolve_attr 从上下文字典取值，属性不存在时返回缺失哨兵。compare 按值的实际类型比较，类型不匹配时不成立。eval_condition 在任一被求值的属性缺失时拒绝。eval_rule 在条件成立时返回规则结论，否则返回不适用。combine 按策略声明的合并方式汇总。validate_policy 返回问题描述列表，无问题时为空列表。abac_batch 按输入顺序返回每条请求的结论，同一请求重复求值结果一致。

## 运行

在仓库根目录执行 python -m pytest tests -q。

## 字段表

| 字段 | 取值 |
| --- | --- |
| 所属领域 | 安全 |
| 子方向 | 漏洞检测与攻防 |
| 任务类型 | Bugfix |
| 语言/框架 | Python 3, pytest |
| 环境可复现等级 | 无外部依赖 |

