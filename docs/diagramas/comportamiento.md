
flowchart TD
    A["Iniciar aplicación"] --> B["Mostrar menú CLI"]
    B --> C["Seleccionar generar eventos"]
    C --> D["Solicitar cantidad"]
    D --> E{"¿Cantidad válida?"}

    E -- No --> D
    E -- Sí --> F["Generar eventos académicos"]
    F --> G["Calcular hash de cada payload"]
    G --> H["Construir log JSON"]
    H --> I["Serializar log"]
    I --> J["Guardar log_plain.json"]
    J --> K["Calcular SHA-256 del archivo"]
    K --> L["Guardar log_plain.sha256"]
    L --> M["Mostrar resultado"]
    M --> B
