# Migración de Prowler CLI + SDK a Go

Estado: propuesta para revisión
Rama: `test-go` (base `origin/master` @ 3c0cb3c)

## 1. Punto de partida medido

| Métrica | Valor |
|---|---|
| LOC Python en `prowler/` | 121.006 |
| Ficheros Python | 3.278 |
| Checks (`*.metadata.json`) | 1.181 |
| Servicios (`*_service.py`) | 169 |
| Proveedores | 14 |
| Frameworks de compliance | 86 |
| Fixers | 55 |
| Flags de CLI | ~170 (30 comunes + 140 por proveedor) |
| LOC de tests | 325.762 en 1.545 ficheros |
| Reparto del código | ~33.7k LOC recolección de datos / ~44.8k LOC lógica de checks |

Checks por proveedor: aws 580, azure 166, gcp 100, kubernetes 83, m365 72,
alibabacloud 63, oraclecloud 51, cloudflare 29, github 20, mongodbatlas 10,
nhn 6, openstack 1, iac y llm sin checks estáticos.

## 2. Decisiones tomadas

1. **Consumo desde el API Django**: el SDK Go se entrega como binario con
   contrato JSON estable. `api/` deja de importar Python y pasa a invocar el
   binario con salida NDJSON en streaming. Sin CGo, sin daemon nuevo.
2. **Alcance**: núcleo y los 14 proveedores en el mismo esfuerzo, no en fases
   secuenciales por proveedor.
3. **Checks custom**: registro estático generado en compilación para los checks
   nativos; `--checks-folder` pasa a un motor declarativo (YAML + CEL) que
   evalúa sobre el modelo de recursos ya recolectado.

## 3. Arquitectura objetivo

```
prowler-go/
  go.mod
  cmd/prowler/                  binario único
  internal/cli/                 cobra: comandos, flags, validación, banner
  internal/codegen/             genera registro de checks y barrels de import
  pkg/
    check/                      Check, Metadata, Registry, Severity
    finding/                    Finding y proyecciones a formatos de salida
    scan/                       motor: planificación, ejecución, progreso
    compliance/                 modelos y agregación de los 86 frameworks
    mutelist/                   evaluación de mutelist
    output/                     csv, ocsf, asff, html, json, tablas resumen
    integration/                securityhub, s3, slack, jira, shodan
    provider/
      provider.go               interfaz Provider
      aws/                      sesión, identidad, regiones, organizations
        service/                75 clientes de servicio
        checks/                 580 checks
      azure/ gcp/ kubernetes/ m365/ github/ cloudflare/ oraclecloud/
      openstack/ alibabacloud/ nhn/ mongodbatlas/ iac/ llm/
  testdata/                     cassettes HTTP y golden outputs
```

Módulo Go independiente en `prowler-go/` para no interferir con el árbol
Python durante la convivencia.

### 3.1 Modelo de check

```go
type Check interface {
    Metadata() *check.Metadata
    Requires() []service.ID
    Execute(ctx context.Context, s *scan.Session) ([]finding.Report, error)
}
```

Cada check se auto-registra en su `init()`. `internal/codegen` lee los 1.181
`*.metadata.json`, los incrusta con `go:embed`, valida el esquema en tiempo de
compilación y genera el barrel de imports por proveedor. Se elimina el import
dinámico por nombre de Python sin perder el descubrimiento automático.

### 3.2 Ciclo de vida de los servicios

Python construye singletons a nivel de módulo al importar (`s3_client = S3(...)`),
lo que fuerza a recolectar servicios que quizá no se necesitan. En Go:

- El planificador deriva del conjunto de checks seleccionados el conjunto
  mínimo de servicios.
- Cada servicio se inicializa una vez por escaneo (`sync.Once`) y solo si algún
  check lo pide.
- Cuando el último check de un servicio termina, su almacén de recursos se
  libera explícitamente antes de pasar al siguiente servicio.

Esto acota el pico de memoria al servicio más pesado en vuelo, no a la suma de
todos los servicios del escaneo.

### 3.3 Gestión de memoria

Requisito explícito del encargo. Reglas que se aplican de forma sistemática:

- **Findings en streaming**: el motor emite por `chan finding.Finding` hacia los
  escritores. En ningún punto existe la lista completa de findings en memoria.
  Los formatos CSV, OCSF, ASFF y JSON escriben incrementalmente sobre `io.Writer`.
  HTML y las tablas resumen, que sí necesitan agregación, mantienen solo
  contadores y agregados, no los findings.
- **Metadatos inmutables y compartidos**: los 1.181 metadatos y los 86
  frameworks se parsean una vez al arrancar a estructuras de solo lectura
  compartidas entre goroutines sin copia ni lock.
- **Tipado estricto en rutas calientes**: structs concretos en vez de
  `map[string]any` e `interface{}` para recursos y findings. El `raw` del
  finding se conserva como `json.RawMessage`, sin deserializar salvo que el
  formato de salida lo requiera.
- **Preasignación**: slices y mapas creados con capacidad conocida a partir del
  recuento de recursos ya paginado.
- **`sync.Pool`** para buffers de codificación y estructuras intermedias de alta
  rotación en los escritores.
- **Concurrencia acotada**: `errgroup` con semáforo por nivel (regiones,
  llamadas de servicio, ejecución de checks) en lugar del `ThreadPoolExecutor`
  sin límite efectivo actual. Evita picos por fan-out de regiones.
- **Presión de GC bajo control**: `debug.SetMemoryLimit` configurable y `GOGC`
  ajustado para escaneos grandes; perfiles de heap en CI sobre el escenario AWS
  completo como test de regresión.
- **Liberación por servicio**: ver 3.2.

### 3.4 Legibilidad

- Paquetes pequeños con una responsabilidad; el nombre del paquete y de la
  función cargan el significado.
- Comentarios solo en la API exportada del SDK y donde haya una decisión no
  obvia. Nada de comentarios que narren el código.
- Errores envueltos con contexto (`fmt.Errorf("...: %w", err)`) en lugar de
  comentarios explicativos.
- Sin abstracciones especulativas: una interfaz aparece cuando hay dos
  implementaciones reales.

## 4. Mapa de dependencias

| Área | Python actual | Equivalente Go |
|---|---|---|
| AWS | boto3/botocore | `aws-sdk-go-v2` |
| Azure | 23 paquetes `azure-mgmt-*` | `azure-sdk-for-go` |
| GCP | `google-api-python-client` | `google-api-go-client`, `cloud.google.com/go` |
| Kubernetes | `kubernetes` | `k8s.io/client-go` |
| GitHub | `pygithub` | `google/go-github` |
| M365 | `msgraph-sdk` + PowerShell | `msgraph-sdk-go` + `pwsh` (sin sustituto) |
| Oracle Cloud | `oci` | `oci-go-sdk` |
| Alibaba Cloud | 12 paquetes `alibabacloud_*` | `alibabacloud-go` |
| Cloudflare | `cloudflare` | `cloudflare-go` |
| OpenStack | `openstacksdk` | `gophercloud` |
| MongoDB Atlas | REST | `atlas-sdk-go` |
| IaC | Trivy por subprocess | Trivy como librería Go |
| Slack / Jira / Shodan | SDKs Python | `slack-go`, `go-jira`, REST |
| OCSF | `py-ocsf-models` | structs propios generados del esquema |
| CLI | argparse | `cobra` + `pflag` |
| Validación | pydantic v1 | validación explícita en constructores |

Ganancia colateral: el proveedor IaC deja de lanzar Trivy como proceso externo
y lo usa como librería.

## 5. Fases

**F0 — Fundamentos**
Módulo Go, layout, CI (build, vet, staticcheck, race, cobertura), herramienta
de codegen, y definición congelada del contrato JSON/NDJSON que consumirá el API.

**F1 — Núcleo del SDK**
`check`, `finding`, `compliance`, `mutelist`, `scan`, `output`. Es la base de la
que dependen las demás fases y donde se materializan las decisiones de memoria.

**F2 — CLI**
Paridad de las ~170 flags, incluidos alias (`--check`/`--checks`, `microsoft365`
→ `m365`, `oci` → `oraclecloud`), proveedor AWS por defecto, códigos de salida
y los modos `--list-*`.

**F3 — Capa de proveedores**
Autenticación, sesión, identidad y configuración regional de los 14. Incluye
assume-role, refresco de credenciales, MFA y Organizations en AWS.

**F4 — Servicios**
169 servicios de recolección. Es el bloque más mecánico y el más paralelizable.

**F5 — Checks y fixers**
1.181 checks y 55 fixers. Cada check debe reproducir su `status_extended`
carácter a carácter.

**F6 — Integraciones**
Security Hub, subida a S3, Slack, Jira, Shodan, mutelist desde DynamoDB/Lambda/S3.

**F7 — Verificación de paridad**
Arnés de golden outputs: mismas cassettes HTTP contra Python y Go, diff de CSV,
OCSF, ASFF y HTML. Port de la suite de tests. Perfiles de memoria comparados.

**F8 — Corte y entrega**
`api/` pasa al binario. Empaquetado multiplataforma, imagen Docker, release.

Dentro de F3–F5 los 14 proveedores avanzan en paralelo; el orden interno lo
marca el volumen: AWS primero por masa crítica, el resto en paralelo detrás.

## 6. Riesgos

| Riesgo | Impacto | Mitigación |
|---|---|---|
| M365 depende de cmdlets de PowerShell en 7 servicios | No hay equivalente Go | Se mantiene `pwsh` como dependencia solo para ese proveedor |
| `dashboard/` (Dash/Plotly) importa el SDK Python | Rompe al retirar Python | Queda fuera de alcance; consume los CSV generados, no el SDK |
| Semántica de validación de pydantic | Diferencias silenciosas en errores | Tests de paridad sobre metadatos y config inválidos |
| Paridad textual de 1.181 `status_extended` | Rompe integraciones y compliance | Golden outputs por check, no solo por escaneo |
| Cobertura desigual de los SDK cloud en Go | Algún endpoint sin cubrir | Auditoría de endpoints en F3, cliente REST propio donde falte |
| Volumen | 121k LOC Python → est. 150–200k LOC Go | Codegen agresivo en servicios y checks; F4/F5 son repetitivos por diseño |
| `--checks-folder` cambia de contrato | Ruptura para usuarios que lo usan | Motor declarativo documentado + guía de migración |

## 7. Criterios de aceptación

- Mismos códigos de salida y mismas flags, incluidos alias y valores por defecto.
- Salidas CSV, OCSF, ASFF y HTML idénticas a las de Python sobre las cassettes
  de referencia, salvo el campo de versión.
- Los 1.181 checks producen el mismo `status` y `status_extended`.
- Los 86 frameworks de compliance producen las mismas agregaciones.
- Pico de memoria por debajo del de la implementación Python en el escenario
  AWS completo, verificado en CI.
- Binario sin dependencia de runtime Python, salvo `pwsh` para M365.
