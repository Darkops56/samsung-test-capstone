"""
Entrenamiento y exportación de modelos Random Forest (NSL-KDD) para uso en Apify.

Uso:
    python entrenar_y_guardar.py                       # modo split (por defecto)
    python entrenar_y_guardar.py --modo full
    python entrenar_y_guardar.py --modo muestra
    python entrenar_y_guardar.py --csv otro.csv --out modelo.pkl --modo split

Genera un único archivo .pkl con:
  - modelo binario (normal / anomaly)
  - modelo multiclase (Normal, DoS, Probe, R2L, U2R)
  - lista y orden exacto de columnas de entrada
  - métricas, modo de entrenamiento y versión de scikit-learn usada

Para predecir con el .pkl desde Apify (u otro lado), ver `cargar_y_predecir()`.
Al final del archivo hay una guía de cómo elegir los parámetros.
"""

import argparse
import datetime
import warnings

import joblib
import numpy as np
import pandas as pd
import sklearn
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report, f1_score, roc_auc_score
from sklearn.model_selection import train_test_split

warnings.filterwarnings("ignore")

SEED = 42
N_MUESTRA = 2000  # tamaño de la muestra estratificada (igual que en el notebook de muestreo)

# Mismas variables que usa entrenamiento_random_forest.py
METRICAS_NUMERICAS = [
    "count", "srv_count", "serror_rate", "srv_serror_rate",
    "rerror_rate", "srv_rerror_rate", "same_srv_rate", "diff_srv_rate", "srv_diff_host_rate",
    "duration", "src_bytes", "dst_bytes",
    "logged_in", "num_failed_logins", "root_shell", "su_attempted",
    "dst_host_count", "dst_host_srv_count", "dst_host_same_srv_rate",
    "dst_host_diff_srv_rate", "dst_host_serror_rate",
]
METRICAS_CATEGORICAS = ["protocol_type", "flag", "service"]
COLUMNAS_ENTRADA = METRICAS_NUMERICAS + METRICAS_CATEGORICAS

CLASES_MULTI = ["Normal", "DoS", "Probe", "R2L", "U2R"]

MODOS = ("split", "full", "muestra")
DESCRIPCION_MODO = {
    "split": "entrenado con 80% de la poblacion; metricas sobre el 20% restante",
    "full": "entrenado con 100% de la poblacion; metricas de una corrida 80/20 previa (no del modelo final)",
    "muestra": f"entrenado con muestra estratificada de ~{N_MUESTRA}; metricas sobre el resto no visto",
}


# ---------------------------------------------------------------- preprocesamiento
def preparar_X(df_entrada: pd.DataFrame, columnas_modelo=None) -> pd.DataFrame:
    """One-hot de las variables categóricas.

    En entrenamiento (columnas_modelo=None) se usa drop_first=True, igual que el script
    original. En predicción se pasa la lista guardada en el .pkl y se alinean las columnas:
    las que faltan quedan en 0 y las que el modelo no conoce se descartan.
    """
    if columnas_modelo is None:
        return pd.get_dummies(df_entrada[COLUMNAS_ENTRADA], drop_first=True)
    X = pd.get_dummies(df_entrada[COLUMNAS_ENTRADA])
    return X.reindex(columns=columnas_modelo, fill_value=0)


def cargar_datos(csv_path: str):
    print(f"[1/4] Cargando {csv_path}...")
    df = pd.read_csv(csv_path)
    X = preparar_X(df)
    y_bin = df["class_binary"].map({"normal": 0, "anomaly": 1})
    y_multi = df["attack_category"]
    print(f"      {len(df):,} registros, {X.shape[1]} columnas codificadas")
    return df, X, y_bin, y_multi


# ---------------------------------------------------------------- modelos
def nuevo_rf_binario():
    return RandomForestClassifier(n_estimators=100, max_depth=15, random_state=SEED, n_jobs=-1)


def nuevo_rf_multiclase():
    return RandomForestClassifier(
        n_estimators=100, max_depth=15, class_weight="balanced_subsample",
        random_state=SEED, n_jobs=-1,
    )


def muestra_estratificada(df: pd.DataFrame, n: int = N_MUESTRA) -> pd.Index:
    """Muestra estratificada proporcional por attack_category (mínimo 1 por estrato).
    Misma lógica que el notebook de muestreo."""
    frac = n / len(df)
    indices = []
    for _, g in df.groupby("attack_category"):
        k = max(1, int(np.round(len(g) * frac)))
        indices.extend(g.sample(n=k, random_state=SEED).index)
    return pd.Index(indices)


def evaluar(rf_bin, rf_multi, Xb_te, yb_te, Xm_te, ym_te):
    metricas = {}
    pred = rf_bin.predict(Xb_te)
    metricas["binario"] = {
        "accuracy": round(accuracy_score(yb_te, pred), 4),
        "f1": round(f1_score(yb_te, pred), 4),
        "roc_auc": round(roc_auc_score(yb_te, rf_bin.predict_proba(Xb_te)[:, 1]), 4),
    }
    pred_m = rf_multi.predict(Xm_te)
    rep = classification_report(ym_te, pred_m, labels=CLASES_MULTI,
                                zero_division=0, output_dict=True)
    metricas["multiclase"] = {
        "accuracy": round(accuracy_score(ym_te, pred_m), 4),
        "f1_por_clase": {c: round(rep[c]["f1-score"], 4) for c in CLASES_MULTI},
    }
    metricas["registros_evaluados"] = int(len(yb_te))
    return metricas


def entrenar(df, X, y_bin, y_multi, modo: str):
    print(f"[2/4] Entrenando en modo '{modo}'...")

    if modo == "muestra":
        idx_tr = muestra_estratificada(df)
        idx_te = df.index.difference(idx_tr)
        print(f"      Entrenamiento: {len(idx_tr):,} registros | Evaluación: {len(idx_te):,} no vistos")
        rf_bin = nuevo_rf_binario().fit(X.loc[idx_tr], y_bin.loc[idx_tr])
        rf_multi = nuevo_rf_multiclase().fit(X.loc[idx_tr], y_multi.loc[idx_tr])
        metricas = evaluar(rf_bin, rf_multi, X.loc[idx_te], y_bin.loc[idx_te],
                           X.loc[idx_te], y_multi.loc[idx_te])
    else:
        # split y full evalúan con un 80/20 estratificado
        Xb_tr, Xb_te, yb_tr, yb_te = train_test_split(
            X, y_bin, test_size=0.20, random_state=SEED, stratify=y_bin)
        Xm_tr, Xm_te, ym_tr, ym_te = train_test_split(
            X, y_multi, test_size=0.20, random_state=SEED, stratify=y_multi)
        print(f"      Entrenamiento: {len(Xb_tr):,} registros | Evaluación: {len(Xb_te):,} no vistos")
        rf_bin = nuevo_rf_binario().fit(Xb_tr, yb_tr)
        rf_multi = nuevo_rf_multiclase().fit(Xm_tr, ym_tr)
        metricas = evaluar(rf_bin, rf_multi, Xb_te, yb_te, Xm_te, ym_te)

        if modo == "full":
            print(f"      Reentrenando con el 100% de los datos ({len(X):,} registros)...")
            rf_bin = nuevo_rf_binario().fit(X, y_bin)
            rf_multi = nuevo_rf_multiclase().fit(X, y_multi)

    print(f"      Binario    -> {metricas['binario']}")
    print(f"      Multiclase -> accuracy {metricas['multiclase']['accuracy']}, "
          f"F1 por clase {metricas['multiclase']['f1_por_clase']}")
    if metricas["multiclase"]["f1_por_clase"]["U2R"] == 0:
        print("      AVISO: U2R no se detecta (muy pocos casos en el dataset).")
    if modo == "full":
        print("      NOTA: las métricas son de la corrida 80/20, no del modelo final (ya vio todos los datos).")

    return rf_bin, rf_multi, metricas


# ---------------------------------------------------------------- guardado
def guardar(rf_bin, rf_multi, X, metricas, modo, ruta):
    paquete = {
        "modelo_binario": rf_bin,
        "modelo_multiclase": rf_multi,
        "columnas_entrada": COLUMNAS_ENTRADA,   # columnas crudas que debe traer cada conexión
        "columnas": list(X.columns),            # columnas codificadas, en orden exacto
        "clases_binario": {0: "normal", 1: "anomaly"},
        "clases_multiclase": list(rf_multi.classes_),
        "modo_entrenamiento": modo,
        "descripcion_modo": DESCRIPCION_MODO[modo],
        "metricas": metricas,
        "sklearn_version": sklearn.__version__,
        "entrenado": datetime.date.today().isoformat(),
    }
    joblib.dump(paquete, ruta, compress=3)
    print(f"[3/4] Guardado: {ruta}  (modo: {modo})")


# ---------------------------------------------------------------- carga y predicción
def cargar_y_predecir(ruta_pkl: str, conexiones: pd.DataFrame) -> pd.DataFrame:
    """Carga el .pkl y predice. `conexiones` debe tener las columnas de COLUMNAS_ENTRADA."""
    paquete = joblib.load(ruta_pkl)

    if paquete["sklearn_version"] != sklearn.__version__:
        print(f"AVISO: el modelo se entrenó con scikit-learn {paquete['sklearn_version']} "
              f"y acá hay {sklearn.__version__}.")

    faltan = [c for c in paquete["columnas_entrada"] if c not in conexiones.columns]
    if faltan:
        raise ValueError(f"Faltan columnas de entrada: {faltan}")

    X = preparar_X(conexiones, paquete["columnas"])
    return pd.DataFrame({
        "es_ataque": paquete["modelo_binario"].predict(X),
        "prob_ataque": paquete["modelo_binario"].predict_proba(X)[:, 1].round(4),
        "categoria": paquete["modelo_multiclase"].predict(X),
    }, index=conexiones.index)


def verificar(ruta_pkl, df, rf_bin, rf_multi, X, n=500):
    """Chequea que el modelo cargado del .pkl prediga igual que el que está en memoria."""
    print("[4/4] Verificando que el .pkl cargado coincida con el modelo en memoria...")
    muestra = df.sample(n=min(n, len(df)), random_state=SEED)
    desde_pkl = cargar_y_predecir(ruta_pkl, muestra)

    Xm = X.loc[muestra.index]
    ok_bin = (desde_pkl["es_ataque"].values == rf_bin.predict(Xm)).all()
    ok_multi = (desde_pkl["categoria"].values == rf_multi.predict(Xm)).all()
    if not (ok_bin and ok_multi):
        raise RuntimeError("El modelo cargado NO coincide con el modelo en memoria.")
    print(f"      OK: {len(muestra)} filas, predicciones idénticas.")
    print("\nEjemplo de salida:")
    print(desde_pkl.head())


# ---------------------------------------------------------------- main
if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Entrena y exporta los Random Forest a un .pkl")
    ap.add_argument("--csv", default="nsl_kdd_20percent_curado.csv",
                    help="ruta al CSV curado (default: nsl_kdd_20percent_curado.csv)")
    ap.add_argument("--out", default="modelo_nids.pkl",
                    help="nombre del .pkl de salida (default: modelo_nids.pkl)")
    ap.add_argument("--modo", choices=MODOS, default="split",
                    help="con qué datos se entrena el modelo guardado (default: split)")
    args = ap.parse_args()

    df, X, y_bin, y_multi = cargar_datos(args.csv)
    rf_bin, rf_multi, metricas = entrenar(df, X, y_bin, y_multi, args.modo)
    guardar(rf_bin, rf_multi, X, metricas, args.modo, args.out)
    verificar(args.out, df, rf_bin, rf_multi, X)


# =====================================================================================
# GUÍA DE PARÁMETROS: CÓMO USARLOS CORRECTAMENTE
# =====================================================================================
#
# --modo  (con qué datos queda entrenado el modelo que se guarda en el .pkl)
#
#   split   (por defecto)  Entrena con el 80% de la población y mide con el 20% restante.
#                          Las métricas del .pkl corresponden EXACTAMENTE al modelo guardado.
#                          Usalo para: la entrega del trabajo y para defender resultados.
#
#   full                   Mide con un 80/20 y después REENTRENA con el 100% de los datos.
#                          El modelo guardado es mejor (vio todo), pero sus métricas
#                          guardadas son de la corrida 80/20, no del modelo final.
#                          Usalo para: dejar el modelo en producción (Apify), una vez que ya
#                          validaste las métricas con el modo split.
#
#   muestra                Entrena solo con la muestra estratificada (~2.000 registros) y
#                          evalúa sobre los ~23.000 restantes que nunca vio.
#                          Usalo para: demostrar que el muestreo estratificado ahorra >90%
#                          de datos sin perder capacidad. Ojo: con 2.000 registros U2R tiene
#                          1 solo caso y R2L pocos, así que NO lo uses como modelo final.
#
# --csv   Ruta al CSV curado. Solo cambialo si el archivo está en otra carpeta o tiene otro
#         nombre. Debe tener las columnas de entrada, class_binary y attack_category.
#
# --out   Nombre del .pkl de salida. Usá nombres distintos por modo para no pisar archivos
#         (por ejemplo modelo_split.pkl, modelo_full.pkl, modelo_muestra.pkl).
#
# EJEMPLOS
#   python entrenar_y_guardar.py
#   python entrenar_y_guardar.py --modo split   --out modelo_split.pkl
#   python entrenar_y_guardar.py --modo full    --out modelo_full.pkl
#   python entrenar_y_guardar.py --modo muestra --out modelo_muestra.pkl
#   python entrenar_y_guardar.py --csv datos/nsl_kdd_20percent_curado.csv --modo full
#
# RECOMENDACIÓN DE FLUJO
#   1) Correr con --modo split y revisar las métricas (esto es lo que se informa).
#   2) Opcional: correr con --modo muestra para mostrar el argumento del muestreo.
#   3) Para Apify, generar el .pkl final con --modo full.
#   4) Usar la MISMA versión de scikit-learn al entrenar y al cargar el .pkl.
#
# PARA PREDECIR (por ejemplo desde Apify)
#   from entrenar_y_guardar import cargar_y_predecir
#   resultado = cargar_y_predecir("modelo_full.pkl", df_conexiones)
#   # df_conexiones debe traer las 24 columnas de COLUMNAS_ENTRADA (21 numéricas + 3 categóricas)
# =====================================================================================
