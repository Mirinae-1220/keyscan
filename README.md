# keyscan

git 레포의 파일에서 비밀값(API 키, 봇 토큰, 개인키)을 찾아 커밋 전에 막고, 찾은 키를 어디서 폐기하고 재발급하는지 알려 주는 CLI입니다.

- 단일 실행 파일, 명령 한 줄
- 찾은 값은 어디에도 그대로 출력하지 않습니다. 앞 4자만 남기고 가립니다
- 찾으면 종료 코드 1로 끝나므로 pre-commit 훅과 CI에서 바로 쓸 수 있습니다
- 찾은 키가 진짜로 쓰이는지 서비스에 보내 확인하지 않습니다. 남의 키를 검증하는 데 악용될 수 있어서입니다

이미 [gitleaks](https://github.com/gitleaks/gitleaks), [trufflehog](https://github.com/trufflesecurity/trufflehog) 같은 완성도 높은 도구가 있습니다. keyscan은 규칙 수보다 디스코드 봇과 국내 API를 쓰는 개인·소규모 팀 개발자에게 맞춘 기본값과 재발급 안내에 집중합니다.

## 설치

Rust가 필요합니다([rustup](https://rustup.rs)).

```sh
cargo install --git https://github.com/Mirinae-1220/keyscan
```

## 사용법

### 커밋 전에 막기

```sh
cd 내-레포
keyscan install-hook
```

`.git/hooks/pre-commit`에 `keyscan staged`를 부르는 훅을 씁니다. 이후 커밋할 때마다 이번 커밋에서 새로 추가된 줄만 검사하고, 비밀값이 있으면 커밋이 막힙니다. 이미 pre-commit 훅이 있으면 덮어쓰지 않고 멈추니, 기존 훅에 `keyscan staged` 줄을 직접 추가하세요.

훅 없이 직접 돌릴 수도 있습니다.

```sh
git add .
keyscan staged
```

### 레포 전체 검사

```sh
keyscan scan          # 현재 폴더
keyscan scan 경로     # 다른 폴더
```

git이 관리하는 파일과, 아직 `git add` 하지 않았지만 `.gitignore`에 들어 있지 않은 새 파일을 검사합니다. `.gitignore`에 들어간 파일(예: `.env`)은 커밋되지 않으므로 검사하지 않습니다. git 레포가 아닌 폴더는 숨김 파일까지 폴더 전체를 검사합니다. 바이너리 파일(앞 8000바이트에 NUL이 있는 파일)은 건너뜁니다.

### 출력 예시

```
[high] discord-bot-token  디스코드 봇 토큰
  .env:1             MTQw****
  src/config.rs:12   MTU0****
  해결: Discord Developer Portal > Applications > 해당 앱 > Bot에서 Reset Token으로 재발급

2건 발견 (파일 48개 검사)
```

### 종료 코드

- `0`: 찾은 것 없음
- `1`: 하나 이상 찾음
- `2`: 실행 오류(git 없음, 설정 파일 오류, 읽지 못한 파일이 있음 등). 비밀값을 찾았으면 다른 오류가 있어도 `1`입니다

### 옵션

- `--config <파일>`: 설정 파일 경로. 기본은 레포 최상위의 `.keyscan.toml`(있을 때만)
- `--min-severity high|medium|low`: 이 위험도 이상만 보고. 기본 `low`

## GitHub Actions

훅을 깔지 않은 사람의 PR도 걸러지도록 CI에서 한 번 더 검사합니다.

```yaml
- uses: actions/checkout@v4
- uses: dtolnay/rust-toolchain@stable
- run: cargo install --git https://github.com/Mirinae-1220/keyscan
- run: keyscan scan
```

## 기본 규칙

- `github-token` (high): GitHub 토큰 `ghp_`, `gho_`, `ghu_`, `ghs_`, `ghr_`
- `github-fine-grained-pat` (high): GitHub 세분화 토큰 `github_pat_`
- `google-api-key` (high): Google API 키 `AIza`
- `aws-access-key-id` (high): AWS 액세스 키 ID `AKIA`, `ASIA`
- `discord-bot-token` (high): 디스코드 봇 토큰(점으로 이어진 세 부분)
- `discord-webhook` (medium): 디스코드 웹훅 주소
- `private-key` (high): `-----BEGIN ... PRIVATE KEY-----` 헤더

규칙은 [`src/rules.toml`](src/rules.toml)에 있습니다.

## 설정

레포 최상위에 `.keyscan.toml`을 두면 기본 규칙을 끄거나 규칙을 추가할 수 있습니다.

```toml
disable = ["discord-webhook"]

[[rule]]
id = "kakao-rest-api-key"
name = "카카오 REST API 키"
regex = '\b[0-9a-f]{32}\b'
keywords = ["kakao"]     # 같은 줄에 이 단어가 있을 때만 걸림(대소문자 무시)
severity = "high"        # high | medium | low
fix = "카카오 디벨로퍼스 > 내 애플리케이션 > 앱 키에서 재발급"
```

정규식에 `(?P<secret>...)` 이름 그룹이 있으면 그 부분만 가린 값으로 보여 줍니다.

## 무시하기

- `.keyscanignore`: 레포 최상위에 두고 `.gitignore`와 같은 문법으로 무시할 경로를 적습니다
- 줄 끝에 `keyscan:allow`를 적으면 그 줄만 무시합니다

```python
EXAMPLE = "AKIA..."  # keyscan:allow
```

## 비밀값을 찾았다면

파일에서 지우고 커밋하는 것만으로는 부족합니다. 커밋 기록에 남고, 이미 다른 사람이나 봇이 복제했을 수 있습니다. 찾은 키는 무조건 폐기하고 재발급하세요. keyscan은 커밋 기록을 직접 고치지 않습니다.

## 한계

- 규칙에 있는 형식만 잡습니다. 모든 비밀값을 잡는다고 보장하지 않습니다
- 인코딩되거나 여러 줄에 나뉜 비밀값은 잡지 못합니다
- 아직 커밋 기록 전체(`git log`)는 검사하지 않습니다. 현재 파일과 스테이지된 변경만 봅니다
- 형식이 흔한 키(예: 32자리 16진수)는 기본 규칙에 없습니다. `keywords`를 쓴 사용자 규칙으로 추가하세요

## 라이선스

[MIT](LICENSE-MIT) 또는 [Apache-2.0](LICENSE-APACHE) 중 원하는 쪽을 따릅니다.
