import React from 'react';
import { Shield } from 'lucide-react';

export default function LoadingSpinner({ message = "Processing security analytics..." }) {
  return (
    <div className="flex flex-col items-center justify-center p-12 space-y-4">
      <div className="relative">
        <div className="w-12 h-12 rounded-full border-2 border-[#282c40] border-t-indigo-500 animate-spin"></div>
        <div className="absolute inset-0 flex items-center justify-center">
          <Shield className="w-5 h-5 text-indigo-400" />
        </div>
      </div>
      <p className="text-xs text-slate-500 font-mono tracking-wider">
        {message}
      </p>
    </div>
  );
}
