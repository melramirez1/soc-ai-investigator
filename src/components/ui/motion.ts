/**
 * Tokens de movimiento (Emil Kowalski / Linear).
 * Todo el movimiento de la UI usa resortes: nunca curvas ease genericas.
 */

import type { Transition, Variants } from "framer-motion";

/** Resorte "snappy": respuesta inmediata sin rebote perceptible. */
export const SPRING_SNAPPY: Transition = { type: "spring", stiffness: 350, damping: 25 };

/** Resorte del indicador de pestana activa (estilo macOS / Linear). */
export const SPRING_TAB: Transition = { type: "spring", stiffness: 380, damping: 30, mass: 0.8 };

/** Escala de pulsacion tactil. */
export const TAP_SCALE = 0.98;

/** Contenedor que escalona la entrada de sus hijos. */
export const staggerContainer: Variants = {
  hidden: {},
  show: {
    transition: { staggerChildren: 0.055, delayChildren: 0.04 },
  },
};

/**
 * Hijo escalonado: entrada sutil (fade + rise).
 * Sin `filter`: un filtro en un ancestro rompe el `backdrop-filter` del cristal.
 */
export const staggerItem: Variants = {
  hidden: { opacity: 0, y: 10 },
  show: {
    opacity: 1,
    y: 0,
    transition: SPRING_SNAPPY,
  },
};
