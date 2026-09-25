import React from 'react';

export default function ProtectedRoute({ children }) {
  // Direct access with zero login/sign-in gating required
  return children;
}
