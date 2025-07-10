'use client';

import { Button } from '@/components/ui/button';
import { getMe } from '@/api/api';
import React, { useState, useEffect } from 'react';
import Link from 'next/link';

export function Header() {
  const [authorized, setAuthorized] = useState(false);

  async function checkAuth() {
    try {
      await getMe();
      setAuthorized(true);
    } catch {
      setAuthorized(false);
    }
  }

  useEffect(() => {
    checkAuth();

    function onAuthChange() {
      checkAuth();
    }

    window.addEventListener('authChanged', onAuthChange);
    return () => window.removeEventListener('authChanged', onAuthChange);
  }, []);

  return (
    <header className="bg-white shadow py-4" style={{background: 'black'}}>
      <div className="container mx-auto flex justify-between items-center px-4">
        <Link href="/">
          <span className="text-xl font-semibold">Private Cloud</span>
        </Link>
        <div className="space-x-4">
          {!authorized ? (
            <>
              <Button asChild variant="outline">
                <Link href="/login">Авторизация</Link>
              </Button>
              <Button asChild>
                <Link href="/register">Регистрация</Link>
              </Button>
            </>
          ) : (
            <>
              <Button asChild>
                <Link href="/dashboard">Личный кабинет</Link>
              </Button>
              <Button asChild variant="outline">
                <Link href="/logout">Выход</Link>
              </Button>
            </>
          )}
        </div>
      </div>
    </header>
  );
}