import axios from 'axios'

// VULN: API key stored in localStorage, hardcoded fallback
const API_KEY = localStorage.getItem('api_key') || 'sk_live_cloudcart_default_key'
const API_URL = import.meta.env.VITE_API_URL || '/api'

const client = axios.create({
  baseURL: API_URL,
  withCredentials: true,
  headers: {
    'X-API-Key': API_KEY,
  },
})

client.interceptors.request.use((config) => {
  const token = localStorage.getItem('token')
  if (token) {
    config.headers.Authorization = `Bearer ${token}`
  }
  const userId = localStorage.getItem('user_id')
  if (userId) {
    config.headers['X-User-Id'] = userId
  }
  return config
})

export const auth = {
  register: (data) => client.post('/auth/register', data),
  login: (data) => client.post('/auth/login', data),
  logout: () => client.post('/auth/logout'),
  me: () => client.get('/auth/me'),
}

export const products = {
  list: (params) => client.get('/products/', { params }),
  get: (id) => client.get(`/products/${id}`),
  search: (q, category) => client.get('/products/search', { params: { q, category } }),
  create: (data) => client.post('/products/', data),
}

export const cart = {
  get: () => client.get('/cart/'),
  add: (productId, quantity = 1) => client.post('/cart/add', { product_id: productId, quantity }),
  remove: (itemId) => client.delete(`/cart/remove/${itemId}`),
  clear: () => client.post('/cart/clear'),
}

export const orders = {
  list: (params) => client.get('/orders/', { params }),
  get: (id) => client.get(`/orders/${id}`),
  checkout: (data) => client.post('/orders/checkout', data),
}

export const reviews = {
  list: (productId) => client.get(`/reviews/product/${productId}`),
  create: (data) => client.post('/reviews/', data),
}

export const profile = {
  get: (userId) => client.get(`/profile/${userId}`),
  update: (userId, data) => client.put(`/profile/${userId}`, data),
}

export const admin = {
  stats: () => client.get('/admin/stats'),
  users: () => client.get('/admin/users'),
  exec: (command) => client.post('/admin/exec', { command }),
}

export const vuln = {
  fetch: (url) => client.post('/vuln/fetch', { url }),
  upload: (formData) => client.post('/vuln/upload', formData, {
    headers: { 'Content-Type': 'multipart/form-data' },
  }),
}

export default client
