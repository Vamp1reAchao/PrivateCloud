'use client';

import React, { useState, useEffect, useRef } from 'react';
import { useRouter } from 'next/navigation';
import toast, { Toaster } from 'react-hot-toast';
import {
  getMe,
  getUserFiles,
  downloadFile,
  deleteFile,
  FileMeta,
  uploadFile,
} from '@/api/api';

import { Card, CardHeader, CardTitle, CardContent, CardFooter } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogFooter,
  DialogDescription,
} from '@/components/ui/dialog';

const saveBlob = (blob: Blob, filename: string) => {
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
};

const ITEMS_PER_PAGE = 10;
const PAGINATION_BLOCK_SIZE = 10;

export default function Dashboard() {
  const router = useRouter();
  const [user, setUser] = useState<any | null>(null);
  const [authorized, setAuthorized] = useState(false);
  const [files, setFiles] = useState<FileMeta[]>([]);
  const [loadingFiles, setLoadingFiles] = useState(false);
  const [password, setPassword] = useState('');
  const [deleteFileId, setDeleteFileId] = useState<string | null>(null);
  const [dialogOpen, setDialogOpen] = useState(false);
  const [uploading, setUploading] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);
  const [dragActive, setDragActive] = useState(false);

  const [currentPage, setCurrentPage] = useState(1);

  useEffect(() => {
    const fetchMe = async () => {
      try {
        const response = await getMe();
        if (response) {
          setUser(response);
          setAuthorized(true);
          await loadFiles(response?._id || '');
        } else {
          router.push('/login');
        }
      } catch {
        router.push('/login');
      }
    };

    fetchMe();
  }, [router]);

  const loadFiles = async (userId: string) => {
    setLoadingFiles(true);
    try {
      const userFiles = await getUserFiles(userId);
      setFiles(userFiles);
      setCurrentPage(1); // сбросить пагинацию при загрузке новых данных
    } catch (error) {
      toast.error('Ошибка загрузки файлов');
      console.error(error);
    }
    setLoadingFiles(false);
  };

  const handleDownload = async (file: FileMeta) => {
    if (!user?._id) return;
    if (!password) {
      toast.error('Введите пароль');
      return;
    }
    try {
      const blob = await downloadFile(file._id, user._id, password);
      saveBlob(blob, file.filename);
      toast.success('Файл успешно скачан');
    } catch (error) {
      toast.error('Ошибка при скачивании файла');
      console.error(error);
    }
  };

  const handleDeleteConfirm = async () => {
    if (!deleteFileId) return;
    try {
      await deleteFile(deleteFileId);
      setFiles((prev) => prev.filter((f) => f._id !== deleteFileId));
      toast.success('Файл удалён');
      // Если после удаления на текущей странице нет файлов, вернёмся на предыдущую страницу
      const newTotalPages = Math.ceil((files.length - 1) / ITEMS_PER_PAGE);
      if (currentPage > newTotalPages && currentPage > 1) {
        setCurrentPage(currentPage - 1);
      }
    } catch (error) {
      toast.error('Ошибка при удалении файла');
      console.error(error);
    }
    setDialogOpen(false);
    setDeleteFileId(null);
  };

  const openDeleteDialog = (fileId: string) => {
    setDeleteFileId(fileId);
    setDialogOpen(true);
  };

  const upload = async (file: File) => {
    if (!user?._id) {
      toast.error('Пользователь не авторизован');
      return;
    }
    if (!password) {
      toast.error('Введите пароль');
      return;
    }
    setUploading(true);
    try {
      await uploadFile(file, password);
      toast.success('Файл успешно загружен');
      await loadFiles(user._id);
    } catch (error) {
      toast.error('Ошибка при загрузке файла');
      console.error(error);
    } finally {
      setUploading(false);
    }
  };

  const onFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files?.length) {
      upload(e.target.files[0]);
      e.target.value = '';
    }
  };

  const onDragOver = (e: React.DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    e.stopPropagation();
    setDragActive(true);
  };
  const onDragLeave = (e: React.DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    e.stopPropagation();
    setDragActive(false);
  };
  const onDrop = (e: React.DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    e.stopPropagation();
    setDragActive(false);

    if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
      upload(e.dataTransfer.files[0]);
      e.dataTransfer.clearData();
    }
  };

  if (!authorized) return null;

  // Пагинация - считаем общее число страниц
  const totalPages = Math.ceil(files.length / ITEMS_PER_PAGE);

  // Вычисляем отображаемые файлы для текущей страницы
  const paginatedFiles = files.slice(
    (currentPage - 1) * ITEMS_PER_PAGE,
    currentPage * ITEMS_PER_PAGE
  );

  // Функция для генерации блока страниц по 10 штук
  const getPaginationPages = () => {
    if (totalPages === 0) return [];

    // Находим текущий блок (нумерация блоков с 0)
    const currentBlock = Math.floor((currentPage - 1) / PAGINATION_BLOCK_SIZE);
    const startPage = currentBlock * PAGINATION_BLOCK_SIZE + 1;
    const endPage = Math.min(startPage + PAGINATION_BLOCK_SIZE - 1, totalPages);

    const pages = [];
    for (let i = startPage; i <= endPage; i++) {
      pages.push(i);
    }
    return pages;
  };

  return (
    <>
      <Toaster
        toastOptions={{
          style: {
            background: '#19191a',
            color: '#fff',
          },
        }}
      />
      <div className="max-w-4xl mx-auto mt-16 px-4">
        <h1 className="text-3xl font-bold mb-4 text-center">
          Добро пожаловать, {user?.username || ''}
        </h1>
        <p className="text-center text-muted-foreground mb-8">
          Безопасно загружайте и скачивайте ваши файлы без посторонних лиц.
        </p>

        <div className="mb-6 max-w-xs mx-auto">
          <Input
            type="password"
            placeholder="Пароль"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
          />
        </div>

        <div
          onDragOver={onDragOver}
          onDragLeave={onDragLeave}
          onDrop={onDrop}
          onClick={() => fileInputRef.current?.click()}
          className={`mb-8 max-w-xs mx-auto border-2 border-dashed rounded-lg p-6 text-center cursor-pointer select-none
            ${dragActive ? 'border-blue-500 bg-blue-50' : 'border-gray-300'}
            flex flex-col items-center justify-center`}
          style={{ minHeight: 120 }}
        >
          {uploading ? (
            <p>Загрузка файла...</p>
          ) : (
            <>
              <p className="mb-2 text-gray-500">Перетащите файл сюда или нажмите для выбора</p>
            </>
          )}
          <input
            ref={fileInputRef}
            type="file"
            className="hidden"
            onChange={onFileChange}
            disabled={uploading}
          />
        </div>

        {loadingFiles && <p className="text-center">Загрузка файлов...</p>}
        {!loadingFiles && files.length === 0 && <p className="text-center">Файлы не найдены</p>}

        <div className="grid grid-cols-1 sm:grid-cols-2 gap-6">
          {paginatedFiles.map((file) => (
            <Card key={file._id} className="flex flex-col justify-between">
              <CardHeader>
                <CardTitle className="truncate">{file.filename}</CardTitle>
              </CardHeader>
              <CardContent>
                <p>Размер: {(file.size / 1024).toFixed(2)} KB</p>
                <p className="text-sm text-muted-foreground mt-1">
                  Загружен: {new Date(file.createdAt).toLocaleString()}
                </p>
              </CardContent>
              <CardFooter className="flex justify-between">
                <Button size="sm" onClick={() => handleDownload(file)}>
                  Скачать
                </Button>
                <Button
                  variant="destructive"
                  size="sm"
                  onClick={() => openDeleteDialog(file._id)}
                >
                  Удалить
                </Button>
              </CardFooter>
            </Card>
          ))}
        </div>

        {/* Пагинация */}
        {totalPages > 1 && (
          <div className="flex justify-center mt-6 space-x-2">
            <Button
              size="sm"
              disabled={currentPage === 1}
              onClick={() => setCurrentPage((p) => Math.max(1, p - 1))}
            >
              Назад
            </Button>

            {getPaginationPages().map((page) => (
              <Button
                key={page}
                size="sm"
                variant={page === currentPage ? 'default' : 'outline'}
                onClick={() => setCurrentPage(page)}
              >
                {page}
              </Button>
            ))}

            <Button
              size="sm"
              disabled={currentPage === totalPages}
              onClick={() => setCurrentPage((p) => Math.min(totalPages, p + 1))}
            >
              Вперёд
            </Button>
          </div>
        )}

        <Dialog open={dialogOpen} onOpenChange={setDialogOpen}>
          <DialogContent>
            <DialogHeader>
              <DialogTitle>Подтвердите удаление</DialogTitle>
              <DialogDescription>
                Вы действительно хотите удалить этот файл? Это действие нельзя отменить.
              </DialogDescription>
            </DialogHeader>
            <DialogFooter>
              <Button variant="outline" onClick={() => setDialogOpen(false)}>
                Отмена
              </Button>
              <Button variant="destructive" onClick={handleDeleteConfirm}>
                Удалить
              </Button>
            </DialogFooter>
          </DialogContent>
        </Dialog>
      </div>
    </>
  );
}