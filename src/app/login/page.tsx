'use client';

import { useState } from 'react';
import { useForm } from 'react-hook-form';
import { z } from 'zod';
import { zodResolver } from '@hookform/resolvers/zod';
import { useRouter } from 'next/navigation';

import { Input } from '@/components/ui/input';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Label } from '@/components/ui/label';

import { login, getMe } from '@/api/api';

import { useEffect } from 'react';

const loginSchema = z.object({
  username: z.string().min(3, 'Логин обязателен'),
  password: z.string().min(6, 'Пароль должен быть длинной не менее чем 6 символов'),
});

type LoginFormData = z.infer<typeof loginSchema>;

export default function LoginPage() {
  const {
    register,
    handleSubmit,
    formState: { errors },
  } = useForm<LoginFormData>({
    resolver: zodResolver(loginSchema),
  });

  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const router = useRouter();

  useEffect(() => {
    const fetchMe = async () => {
      try {
        const response = await getMe();
        if (response) {
          router.push('/dashboard')
        }
      } catch (error: any) {
        console.log(`Error checking authorization: ${error?.message || 'unknown error'}`)
      }
    };

    fetchMe();
  }, [router]);

  const onSubmit = async (data: LoginFormData) => {
    setLoading(true);
    setError('');

    try {
      const response = await login(data);
      if (response?.error) {
        setError(response.error);
        return;
      }

      localStorage.setItem('token', response?.token || '');
      window.dispatchEvent(new Event('authChanged'));
      router.push('/dashboard');
    } catch (err: any) {
      setError(err?.message || 'Ошибка авторизации');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center" style={{marginTop: '40px'}}>
      <Card className="w-full max-w-md">
        <CardHeader>
          <CardTitle className="text-center">Авторизация</CardTitle>
        </CardHeader>
        <CardContent>
          <form onSubmit={handleSubmit(onSubmit)} className="space-y-4">
            <div>
              <Label htmlFor="username">Логин</Label>
              <Input id="username" {...register('username')} />
              {errors.username && <p className="text-sm text-red-500">{errors.username.message}</p>}
            </div>
            <div>
              <Label htmlFor="password">Пароль</Label>
              <Input id="password" type="password" {...register('password')} />
              {errors.password && <p className="text-sm text-red-500">{errors.password.message}</p>}
            </div>
            {error && <p className="text-sm text-red-500">{error}</p>}
            <Button type="submit" className="w-full" disabled={loading}>
              {loading ? 'Авторизация...' : 'Авторизоваться'}
            </Button>
          </form>
        </CardContent>
      </Card>
    </div>
  );
}