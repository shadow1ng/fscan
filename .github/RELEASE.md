# 发版流程

正式版由 `main` 的 push 触发：读取 `common/globals.go` 的版本号、创建对应 tag，并在同一次工作流中构建和发布 GitHub Release。

**合并到 `main` 就会开始发布。** 合并前必须更新版本号、准备 Release Notes，并验证包含全部待发布改动的候选提交。测试构建工作流与发布工作流独立，发布不会等待合并后的测试结果。

## 预检查

```bash
# 使用已包含全部待发布改动的分支：dev 或 release/*
RELEASE_REF=release/v2.2.2

# 1. 确认该分支最新提交的测试 CI 通过
gh run list --branch "$RELEASE_REF" --workflow test-build.yml --limit 3

# 2. 全平台 dry-run；必须指定 ref，避免默认构建 main
gh workflow run release.yml --ref "$RELEASE_REF" -f snapshot=true
gh run list --branch "$RELEASE_REF" --workflow release.yml --limit 3

# 3. 在候选分支确认版本号一致，且 Release Notes 已就绪
rg 'version = ' common/globals.go
rg '^\*\*版本\*\*:' README.md
rg '^\*\*Version\*\*:' README_EN.md
cat .github/release-notes/v2.2.2.md

# 4. 新版本 tag 应不存在；已有 tag 不可移动或覆盖
git ls-remote --tags origin refs/tags/v2.2.2
```

等待 snapshot 工作流成功，并核对该次运行的 SHA 与待合并提交一致。产物包括标准版、无本地插件版、Web 版和 SHA256 校验文件；snapshot 不创建 tag 或 GitHub Release。

## 正式版发布

```bash
# 从已验证的候选分支创建 PR
gh pr create --base main --head "$RELEASE_REF"

# 审核通过后合并 PR；此次 main push 会自动打 tag 并发布
# 无需再手动执行 git tag / git push tag

# 跟踪发布任务，确认 Release 与附件完整
gh run list --branch main --workflow release.yml --limit 3
gh release view v2.2.2
```

若工作流提示 tag 已存在且不指向当前提交，说明版本号未递增或该版本已经发布；先核对提交和版本，不能移动已有 tag。若构建失败，在对应 Actions 运行中查看失败步骤。

发布完成后将 `main` 同步回 `dev`，保留已发布提交的历史。手动重跑正式版构建必须指定已有 tag；`draft=true` 仅控制本次手动运行创建草稿，不改变 `main` 合并即发布的行为。

## 预发布

在候选分支准备 RC 版本号与同名 Release Notes，验证后手动推送 `vX.Y.Z-rc.N` tag。tag push 会触发构建，GoReleaser 自动将 RC 标记为 prerelease。

## 版本号规范

| 场景 | 格式 | 分支 | 示例 |
|------|------|------|------|
| 正式版 | `vX.Y.Z` | main | `v2.2.0` |
| 预发布 | `vX.Y.Z-rc` | dev | `v2.2.0-rc` |
| 热修复 | `vX.Y.Z` | main | `v2.2.1` |

## Release Notes 模板

放在 `.github/release-notes/<tag>.md`，格式参考 `v2.2.0-rc.md`。

如果文件不存在，goreleaser 会自动生成基于 commit 的 changelog。
