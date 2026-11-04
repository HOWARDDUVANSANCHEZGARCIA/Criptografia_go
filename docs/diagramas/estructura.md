
flowchart TD
    A["cmd/logsecure<br/>main.go"] --> B["internal/cli"]

    B --> C["internal/pipeline"]
    B --> D["internal/generator"]

    C --> D
    C --> E["internal/logbuilder"]
    C --> F["internal/hashing"]
    C --> G["internal/storage"]

    D --> H["internal/model"]
    E --> H
    F --> H

    I["internal/crypto"] -.-> G
    J["internal/verify"] -.-> F
    K["internal/report"] -.-> B
