import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import { createTheme, CssBaseline, ThemeProvider } from '@mui/material'
import { QueryClientProvider } from '@tanstack/react-query'
import { BrowserRouter } from 'react-router-dom'
import './index.css'
import App from './App.tsx'
import { queryClient } from './lib/queryClient'

const theme = createTheme({
  palette: {
    mode: 'dark',
    primary: { main: '#00d8e8' },
    secondary: { main: '#ffb44a' },
    background: { default: '#090d16', paper: '#0f172a' },
  },
  typography: { fontFamily: '"Plus Jakarta Sans Variable", sans-serif' },
  shape: { borderRadius: 6 },
})

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <ThemeProvider theme={theme}>
      <CssBaseline />
      <QueryClientProvider client={queryClient}>
        <BrowserRouter>
          <App />
        </BrowserRouter>
      </QueryClientProvider>
    </ThemeProvider>
  </StrictMode>,
)
