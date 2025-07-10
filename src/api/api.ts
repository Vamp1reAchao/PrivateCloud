import axios from 'axios';

const API_BASE_URL = process.env.NEXT_PUBLIC_BACKEND_URI;

const api = axios.create({
  baseURL: API_BASE_URL,
  withCredentials: false,
});

// Типы
export interface RegisterData {
  username: string;
  password: string;
}

export interface LoginData {
  username: string;
  password: string;
}

export interface FileMeta {
  _id: string;
  filename: string;
  storedName: string;
  contentType: string;
  size: number;
  createdAt: string;
}

export interface LoginResponse {
  token?: string;
  message?: string;
  error?: string;
}

interface MeResponse {
  _id?: string;
  username?: string;
  createdAt?: Date;
  error?: string;
}

export interface RegisterResponse {
  message: string;
  error?: string;
}

export interface FileUploadResponse {
  message: string;
}

export interface UserFileListResponse extends Array<FileMeta> {}

// Установка JWT токена в localStorage
export function setToken(t: string) {
  localStorage.setItem('token', t);
}

// Получение токена из localStorage
function getToken(): string | null {
  return localStorage.getItem('token');
}

// --- Методы API ---

export const register = async (data: RegisterData): Promise<RegisterResponse> => {
  const res = await api.post<RegisterResponse>('/register', data);
  return res.data;
};

export const login = async (data: LoginData) => {
  const res = await api.post<LoginResponse>('/login', data);
  if (res.data.token) {
    setToken(res.data.token);
  }
  return res.data;
};

export const getMe = async (): Promise<MeResponse> => {
  const token = getToken();
  if (!token) throw new Error('No token set');

  const res = await api.get<MeResponse>(
    '/me',
    {
      headers: {
        Authorization: `Bearer ${token}`,
      },
    }
  );
  return res.data;
};

export const uploadFile = async (file: File, password: string) => {
  const token = getToken();
  if (!token) throw new Error('No token set');

  const formData = new FormData();
  formData.append('file', file);

  const res = await api.post<FileUploadResponse>(
    `/upload?password=${encodeURIComponent(password)}`,
    formData,
    {
      headers: {
        Authorization: `Bearer ${token}`,
        'Content-Type': 'multipart/form-data',
      },
    }
  );

  return res.data;
};

export const downloadFile = async (
  fileId: string,
  userId: string,
  password: string
): Promise<Blob> => {
  const token = getToken();
  if (!token) throw new Error('No token set');

  const res = await api.get(`/download/${fileId}`, {
    params: {
      user_id: userId,
      password,
    },
    headers: {
      Authorization: `Bearer: ${token}`,
    },
    responseType: 'blob',
  });

  return res.data;
};

export const deleteFile = async (fileId: string) => {
  const token = getToken();
  if (!token) throw new Error('No token set');

  const res = await api.delete(`/file/${fileId}`, {
    headers: {
      Authorization: `Bearer ${token}`,
    },
  });

  return res.data;
};

export const getUserFiles = async (userId: string) => {
  const token = getToken();
  if (!token) throw new Error('No token set');

  const res = await api.get<UserFileListResponse>(`/list/${userId}`, {
  headers: {
    Authorization: `Bearer ${token}`,
  }});
  return res.data;
};