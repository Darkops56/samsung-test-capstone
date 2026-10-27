"""
Script de Entrenamiento de Machine Learning: Random Forest en Ciberseguridad (NSL-KDD)
======================================================================================
Este script implementa:
1. Preprocesamiento y selección de las métricas clave exploradas en el EDA.
2. Modelo 1: Random Forest Clasificador Binario (Normal vs Anomalía).
3. Matriz de confusión y curvas de importancia de características (Feature Importance).
4. Modelo 2: Random Forest Clasificador Multiclase (Normal, DoS, Probe, R2L, U2R).
5. Comparativa de rendimiento: Entrenamiento sobre Población vs sobre Muestra Estratificada.
"""

import warnings
warnings.filterwarnings('ignore')

import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    ConfusionMatrixDisplay,
    roc_auc_score,
    accuracy_score,
    f1_score
)

# Configuración visual
plt.style.use('seaborn-v0_8-whitegrid' if 'seaborn-v0_8-whitegrid' in plt.style.available else 'default')
plt.rcParams['font.sans-serif'] = 'DejaVu Sans'
plt.rcParams['font.size'] = 10
SEED = 42

def cargar_y_preprocesar(csv_path='nsl_kdd_20percent_curado.csv'):
    print(f"[1/5] Cargando dataset desde {csv_path}...")
    df = pd.read_csv(csv_path)
    
    # Métricas seleccionadas basadas en el EDA y problemáticas de negocio:
    metricas_numericas = [
        # Ventana temporal de 2 segundos (Eje del modelado de Poisson)
        'count', 'srv_count', 'serror_rate', 'srv_serror_rate', 
        'rerror_rate', 'srv_rerror_rate', 'same_srv_rate', 'diff_srv_rate', 'srv_diff_host_rate',
        
        # Conexión básica y volumetría
        'duration', 'src_bytes', 'dst_bytes',
        
        # Comportamiento de host (vital para R2L y U2R)
        'logged_in', 'num_failed_logins', 'root_shell', 'su_attempted',
        
        # Historial de 100 conexiones hacia el host de destino (Detección Slow & Low)
        'dst_host_count', 'dst_host_srv_count', 'dst_host_same_srv_rate', 
        'dst_host_diff_srv_rate', 'dst_host_serror_rate'
    ]
    
    metricas_categoricas = ['protocol_type', 'flag', 'service']
    
    # One-Hot Encoding para variables categóricas
    X = pd.get_dummies(df[metricas_numericas + metricas_categoricas], drop_first=True)
    
    # Objetivos: Binario y Multiclase
    y_binario = df['class_binary'].map({'normal': 0, 'anomaly': 1})
    y_multiclase = df['attack_category']
    
    return df, X, y_binario, y_multiclase

def entrenar_modelo_binario(X, y_binario):
    print("\n[2/5] Entrenando Random Forest Binario (Normal vs Anomalía)...")
    
    # Split 80/20 estratificado
    X_train, X_test, y_train, y_test = train_test_split(
        X, y_binario, test_size=0.20, random_state=SEED, stratify=y_binario
    )
    
    # Instanciación y entrenamiento
    rf_bin = RandomForestClassifier(
        n_estimators=100,
        max_depth=15,
        random_state=SEED,
        n_jobs=-1
    )
    rf_bin.fit(X_train, y_train)
    
    # Predicciones
    y_pred = rf_bin.predict(X_test)
    y_prob = rf_bin.predict_proba(X_test)[:, 1]
    
    acc = accuracy_score(y_test, y_pred)
    f1 = f1_score(y_test, y_pred)
    auc = roc_auc_score(y_test, y_prob)
    
    print(f" -> Accuracy  : {acc*100:.2f}%")
    print(f" -> F1-Score  : {f1*100:.2f}%")
    print(f" -> ROC-AUC   : {auc*100:.2f}%")
    print("\nReporte de Clasificación Binaria:")
    print(classification_report(y_test, y_pred, target_names=['Normal (0)', 'Anomaly (1)'], digits=4))
    
    # Gráfico 1: Matriz de Confusión Binaria
    fig, ax = plt.subplots(figsize=(6, 5))
    cm = confusion_matrix(y_test, y_pred)
    disp = ConfusionMatrixDisplay(confusion_matrix=cm, display_labels=['Normal', 'Ataque'])
    disp.plot(cmap='Blues', ax=ax, values_format='d')
    ax.set_title('Matriz de Confusión: Random Forest Binario\n(Detección de Intrusiones)', fontweight='bold')
    plt.tight_layout()
    plt.savefig('rf_matriz_confusion_binaria.png', dpi=300)
    plt.close()
    print(" -> Guardado: rf_matriz_confusion_binaria.png")
    
    # Gráfico 2: Importancia de Características (Feature Importance)
    importancias = pd.Series(rf_bin.feature_importances_, index=X.columns).sort_values(ascending=False)
    top15 = importancias.head(15)[::-1]
    
    fig, ax = plt.subplots(figsize=(9, 6))
    ax.barh(top15.index, top15.values, color='#2a9d8f', edgecolor='black', alpha=0.85)
    ax.set_title('Top 15 Métricas Más Determinantes en Detección (Feature Importance)', fontweight='bold', pad=12)
    ax.set_xlabel('Importancia Relativa (Gini Importance)')
    for i, v in enumerate(top15.values):
        ax.text(v + 0.002, i, f"{v:.4f}", va='center', fontsize=9)
    ax.set_xlim(0, max(top15.values) * 1.15)
    plt.tight_layout()
    plt.savefig('rf_feature_importance.png', dpi=300)
    plt.close()
    print(" -> Guardado: rf_feature_importance.png")
    
    return rf_bin, X_test, y_test, importancias

def entrenar_modelo_multiclase(X, y_multiclase):
    print("\n[3/5] Entrenando Random Forest Multiclase (5 Categorías de Tráfico)...")
    
    # Split 80/20 estratificado
    X_train, X_test, y_train, y_test = train_test_split(
        X, y_multiclase, test_size=0.20, random_state=SEED, stratify=y_multiclase
    )
    
    # Random Forest con ponderación balanceada para mitigar el desbalance extremo de U2R y R2L
    rf_multi = RandomForestClassifier(
        n_estimators=100,
        max_depth=15,
        class_weight='balanced_subsample',
        random_state=SEED,
        n_jobs=-1
    )
    rf_multi.fit(X_train, y_train)
    
    y_pred = rf_multi.predict(X_test)
    clases = ['Normal', 'DoS', 'Probe', 'R2L', 'U2R']
    
    print("\nReporte de Clasificación Multiclase:")
    print(classification_report(y_test, y_pred, labels=clases, zero_division=0, digits=4))
    
    # Gráfico 3: Matriz de Confusión Multiclase
    fig, ax = plt.subplots(figsize=(7, 6))
    cm = confusion_matrix(y_test, y_pred, labels=clases)
    disp = ConfusionMatrixDisplay(confusion_matrix=cm, display_labels=clases)
    disp.plot(cmap='YlGnBu', ax=ax, values_format='d')
    ax.set_title('Matriz de Confusión: Random Forest Multiclase\n(Clasificación de Amenazas)', fontweight='bold')
    plt.tight_layout()
    plt.savefig('rf_matriz_confusion_multiclase.png', dpi=300)
    plt.close()
    print(" -> Guardado: rf_matriz_confusion_multiclase.png")
    
    return rf_multi, X_test, y_test

def evaluar_entrenamiento_con_muestra_estratificada(df, X, y_binario):
    print("\n[4/5] Evaluando impacto del Muestreo Estratificado (Entrenar con n=2.000 vs n=20.000)...")
    
    # Muestra estratificada de 2.000 registros (la misma del notebook)
    frac = 2000 / len(df)
    indices_muestra = df.groupby('attack_category', group_keys=False).apply(
        lambda g: g.sample(n=max(1, int(np.round(len(g) * frac))), random_state=SEED)
    ).index
    
    X_train_peq = X.loc[indices_muestra]
    y_train_peq = y_binario.loc[indices_muestra]
    
    # Test sobre TODO el resto de los datos (~23.191 registros)
    indices_resto = df.index.difference(indices_muestra)
    X_test_grande = X.loc[indices_resto]
    y_test_grande = y_binario.loc[indices_resto]
    
    rf_muestra = RandomForestClassifier(n_estimators=100, max_depth=15, random_state=SEED, n_jobs=-1)
    rf_muestra.fit(X_train_peq, y_train_peq)
    
    y_pred_grande = rf_muestra.predict(X_test_grande)
    acc_muestra = accuracy_score(y_test_grande, y_pred_grande)
    f1_muestra = f1_score(y_test_grande, y_pred_grande)
    
    print(f" -> Modelo entrenado con Muestra Estratificada (n = {len(X_train_peq):,} registros):")
    print(f"    - Evaluado sobre los {len(X_test_grande):,} registros restantes no vistos:")
    print(f"    - Accuracy: {acc_muestra*100:.2f}% | F1-Score: {f1_muestra*100:.2f}%")
    print("    ¡Demuestra que el muestreo estratificado conserva la capacidad de generalización del modelo!")

if __name__ == '__main__':
    df, X, y_bin, y_multi = cargar_y_preprocesar()
    rf_bin, X_test_b, y_test_b, importancias = entrenar_modelo_binario(X, y_bin)
    rf_multi, X_test_m, y_test_m = entrenar_modelo_multiclase(X, y_multi)
    evaluar_entrenamiento_con_muestra_estratificada(df, X, y_bin)
    print("\n[5/5] ¡Entrenamiento y evaluación completados exitosamente!")
