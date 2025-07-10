'use client';

import { useRouter } from 'next/navigation';
import { useEffect } from 'react';

export default function Logout() {
  const router = useRouter();

  useEffect(() => {
    localStorage.removeItem('token');
    window.dispatchEvent(new Event('authChanged'));
    router.push('/');
  }, []);

  return null;
}