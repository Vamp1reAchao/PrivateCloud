'use client';

import { useRouter } from 'next/navigation';
import { Button } from '@/components/ui/button';

export default function HomePage() {
  const router = useRouter();

  const handleStart = () => {
    router.push('/dashboard');
  };

  return (
    <div className="space-y-6" style={{textAlign: 'center', marginTop: '100px'}}>
      <>
        <h1 className="text-3xl font-bold">Добро пожаловать в &quot;Private Cloud&quot;</h1>
        <p className="text-muted-foreground">Безопасно загружайте и скачивайте ваши файлы без посторонних лиц.</p>
        <Button onClick={handleStart}>Начать сейчас</Button>
      </>
    </div>
  );
}