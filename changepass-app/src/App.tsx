import 'bootstrap-icons/font/bootstrap-icons.css';
import React, { useState, useEffect, useRef } from 'react';
import axios, { AxiosError } from 'axios';
import { Turnstile, TurnstileInstance } from '@marsidev/react-turnstile';
import './App.css';

interface Translation {
  title: string;
  loginUsernameLabel: string;
  loginPasswordLabel: string;
  loginButton: string;
  loginError: string;
  welcome: string;
  usernameLabel: string;
  newPasswordLabel: string;
  confirmLabel: string;
  changePasswordButton: string;
  successMessage: string;
  matchError: string;
  fieldsError: string;
  logoutButton: string;
  loginPlaceholder: string;
  passwordPlaceholder: string;
  newPasswordPlaceholder: string;
  confirmPlaceholder: string;
  passwordRequirement: string;
  azurePendingWarning: string;
  forgotPassword: string;
  resetInstructions: string;
  secretCodeLabel: string;
  secretCodePlaceholder: string;
  submitCodeButton: string;
  invalidCodeError: string;
  validationSuccess: string;
  adminButton: string;
  adminFormTitle: string;
  adminSuccessMessage: string;
  adminErrorMessage: string;
  generateButton: string;
  captchaError: string;
  invalidInputError: string;
  unauthorizedError: string;
  secretCodeTooShort: string;
  secretCodeHasSpaces: string;
  rateLimitError: string;
  logoutError: string;
  serverError: string;
  missingFieldsError: string;
  invalidCaptchaError: string;
  invalidCredentialsError: string;
  passwordChangeError: string;
  generateCodeError: string;
}

interface Translations {
  en: Translation;
  vi: Translation;
}

interface ErrorResponse {
  success: boolean;
  message?: string;
  refreshCaptcha?: boolean;
  errorDetails?: string;
}

function App() {
  const [loginUsername, setLoginUsername] = useState<string>('');
  const [loginPassword, setLoginPassword] = useState<string>('');
  const [loggedIn, setLoggedIn] = useState<boolean>(false);
  const [loginMessage, setLoginMessage] = useState<string>('');
  const [showLoginPassword, setShowLoginPassword] = useState<boolean>(false);
  const [username, setUsername] = useState<string>('');
  const [displayName, setDisplayName] = useState<string>('');
  const [password, setPassword] = useState<string>('');
  const [confirmPassword, setConfirmPassword] = useState<string>('');
  const [message, setMessage] = useState<{ text: string; type: 'success' | 'warning' | 'error' } | null>(null);
  const [showNewPassword, setShowNewPassword] = useState<boolean>(false);
  const [showConfirmPassword, setShowConfirmPassword] = useState<boolean>(false);
  const [language, setLanguage] = useState<'en' | 'vi'>('en');
  const [passwordChanged, setPasswordChanged] = useState<boolean>(false);
  const [isProcessing, setIsProcessing] = useState<boolean>(false);
  const [showResetPopup, setShowResetPopup] = useState<boolean>(false);
  const [secretCode, setSecretCode] = useState<string>('');
  const [resetMessage, setResetMessage] = useState<string>('');
  const [showValidationSuccess, setShowValidationSuccess] = useState<boolean>(false);
  const [isAdmin, setIsAdmin] = useState<boolean>(false);
  const [showAdminForm, setShowAdminForm] = useState<boolean>(false);
  const [targetUsername, setTargetUsername] = useState<string>('');
  const [newSecretCode, setNewSecretCode] = useState<string>('');
  const [adminMessage, setAdminMessage] = useState<{ text: string; type: 'success' | 'error' } | null>(null);
  const [turnstileToken, setTurnstileToken] = useState<string | null>(null);
  const [jwtToken, setJwtToken] = useState<string | null>(null);
  const turnstileRef = useRef<TurnstileInstance | null>(null);

  const translations: Translations = {
    en: {
      title: 'GELEXIMCO - ACCOUNT MANAGEMENT',
      loginUsernameLabel: 'Username: ',
      loginPasswordLabel: 'Password: ',
      loginButton: 'Login',
      loginError: 'Invalid username or password.',
      welcome: 'Welcome... ',
      usernameLabel: 'Username: ',
      newPasswordLabel: 'New Password: ',
      confirmLabel: 'Confirm: ',
      changePasswordButton: 'Change Password',
      successMessage: 'The Windows login password and the password of Email/Office 365 changed successfully for user: ',
      matchError: 'Passwords do not match.',
      fieldsError: 'Please fill in all fields.',
      logoutButton: 'Logout',
      loginPlaceholder: 'Email_account ̶ ̶@̶d̶o̶_̶n̶o̶t̶_̶n̶e̶e̶d̶_̶t̶o̶_̶i̶n̶p̶u̶t̶.̶p̶a̶r̶t̶',
      passwordPlaceholder: 'Enter current password',
      newPasswordPlaceholder: 'Enter new password',
      confirmPlaceholder: 'Re-enter new password',
      passwordRequirement: 'The password must be at least 11 characters long and contain at least three of these four elements: an uppercase letter, a lowercase letter, a number, and a special character. It must also NOT include your USERNAME.',
      azurePendingWarning: 'Windows login password changed, but Email/Office 365 account password might take 24h to sync. Please try again later.',
      forgotPassword: 'Forgot password?',
      resetInstructions: 'Contact the System administrator to receive a secret code for resetting your password. Enter your username exactly as provided, and note that the code is valid for only 20 minutes.',
      secretCodeLabel: 'Secret Code: ',
      secretCodePlaceholder: 'Enter the secret code',
      submitCodeButton: 'Submit Code',
      invalidCodeError: 'The informations were invalid input or expired secret code. Please try again with the exact USERNAME and SECRET CODE or contact the system administrator for helping.',
      validationSuccess: 'The validation was successful, now you can proceed to change your password.',
      adminButton: 'Admin',
      adminFormTitle: 'Generate Secret Code for User',
      adminSuccessMessage: 'Secret code generated successfully',
      adminErrorMessage: 'Failed to generate secret code',
      generateButton: 'Generate',
      captchaError: 'Please complete the CAPTCHA verification.',
      invalidInputError: 'Invalid input. Please avoid using spaces, quotes, semicolons, or backticks.',
      unauthorizedError: 'Session expired or invalid. Please log in again.',
      secretCodeTooShort: 'Secret code must be at least 8 characters long.',
      secretCodeHasSpaces: 'Secret code cannot contain spaces.',
      rateLimitError: 'Too many attempts for this username, please try again after 10 minutes.',
      logoutError: 'Logout failed. Please try again.',
      serverError: 'Server error occurred. Please try again later.',
      missingFieldsError: 'All required fields must be filled.',
      invalidCaptchaError: 'Invalid CAPTCHA verification.',
      invalidCredentialsError: 'Invalid username, password, or secret code.',
      passwordChangeError: 'Failed to change password. Please try again later.',
      generateCodeError: 'Failed to generate secret code. Please try again later.',
    },
    vi: {
      title: 'GELEXIMCO - QUẢN LÝ TÀI KHOẢN',
      loginUsernameLabel: 'Tên đăng nhập: ',
      loginPasswordLabel: 'Mật khẩu: ',
      loginButton: 'Đăng nhập',
      loginError: 'Tên đăng nhập hoặc mật khẩu không đúng.',
      welcome: 'Xin chào nhé, ',
      usernameLabel: 'Tên đăng nhập: ',
      newPasswordLabel: 'Mật khẩu mới: ',
      confirmLabel: 'Xác nhận: ',
      changePasswordButton: 'Đổi mật khẩu',
      successMessage: 'Mật khẩu đăng nhập Windows và Mật khẩu tài khoản Email/Office 365 đã được thay đổi thành công cho người dùng: ',
      matchError: 'Mật khẩu không khớp.',
      fieldsError: 'Vui lòng điền đầy đủ các mục.',
      logoutButton: 'Đăng xuất',
      loginPlaceholder: 'Tài khoản Email ̶ ̶@̶p̶h̶ầ̶̶n̶ ̶k̶h̶ô̶n̶g̶ ̶c̶ầ̶̶n̶.̶n̶h̶ậ̶̶p̶',
      passwordPlaceholder: 'Nhập mật khẩu hiện tại',
      newPasswordPlaceholder: 'Nhập mật khẩu mới',
      confirmPlaceholder: 'Nhập lại mật khẩu mới',
      passwordRequirement: 'Mật khẩu dài tối thiểu 11 ký tự và chứa ít nhất ba trong bốn yếu tố sau: chữ viết hoa, chữ viết thường, số và ký tự đặc biệt. Ngoài ra, KHÔNG ĐƯỢC bao gồm TÊN NGƯỜI DÙNG của bạn.',
      azurePendingWarning: 'Mật khẩu đăng nhập Windows đã được thay đổi, nhưng Mật khẩu tài khoản Email & Office 365 có thể mất tới 24 giờ để cập nhật. Vui lòng thử lại sau.',
      forgotPassword: 'Bạn quên mật khẩu?',
      resetInstructions: 'Vui lòng liên hệ quản trị viên hệ thống để nhận mã xác thực reset mật khẩu. Nhập chính xác tên đăng nhập của bạn, và lưu ý mã chỉ có hiệu lực trong 20 phút.',
      secretCodeLabel: 'Mã xác thực: ',
      secretCodePlaceholder: 'Nhập chuỗi xác thực bí mật được IT cung cấp',
      submitCodeButton: 'Xác nhận mã',
      invalidCodeError: 'Thông tin bạn nhập không hợp lệ hoặc đã hết hạn. Vui lòng thử lại với TÊN ĐĂNG NHẬP và MÃ XÁC THỰC chính xác hoặc liên hệ quản trị viên hệ thống.',
      validationSuccess: 'Xác thực thành công, tiếp theo bạn có thể tiến hành thay đổi mật khẩu.',
      adminButton: 'Quản trị',
      adminFormTitle: 'Tạo mã xác thực cho người dùng',
      adminSuccessMessage: 'Mã xác thực được khởi tạo thành công',
      adminErrorMessage: 'Không thể tạo mã xác thực',
      generateButton: 'Khởi Tạo',
      captchaError: 'Vui lòng hoàn thành xác minh CAPTCHA.',
      invalidInputError: 'Chuỗi ký tự nhập vào không hợp lệ. Vui lòng tránh sử dụng dấu cách, dấu nháy, dấu chấm phẩy hoặc dấu backtick.',
      unauthorizedError: 'Phiên đăng nhập hết hạn hoặc không hợp lệ. Vui lòng đăng nhập lại.',
      secretCodeTooShort: 'Mã xác thực phải dài ít nhất 8 ký tự.',
      secretCodeHasSpaces: 'Mã xác thực không được chứa khoảng trắng.',
      rateLimitError: 'Đã quá 5 lần thử cho tên người dùng này, vui lòng trở lại sau 10 phút.',
      logoutError: 'Đăng xuất thất bại. Vui lòng thử lại.',
      serverError: 'Lỗi máy chủ. Vui lòng thử lại sau.',
      missingFieldsError: 'Tất cả các trường bắt buộc phải được điền.',
      invalidCaptchaError: 'Xác minh CAPTCHA không hợp lệ.',
      invalidCredentialsError: 'Tên đăng nhập, mật khẩu hoặc mã xác thực không hợp lệ.',
      passwordChangeError: 'Không thể thay đổi mật khẩu. Vui lòng thử lại sau.',
      generateCodeError: 'Không thể tạo mã xác thực. Vui lòng thử lại sau.',
    },
  };

  const API_URL = 'http://localhost:3001/api';
  const TURNSTILE_SITE_KEY = '0x4AAAAAABK9_sE3dvA8dmId';

  const sanitizeInput = (input: string): string => {
    if (typeof input !== 'string') return '';
    return input
      .replace(/['";`]/g, '')
      .replace(/\s+/g, ' ')
      .trim();
  };

  const api = axios.create({
    baseURL: API_URL,
    headers: {
      'Content-Type': 'application/json',
    },
  });

  api.interceptors.request.use(
    (config) => {
      if (jwtToken) {
        config.headers.Authorization = `Bearer ${jwtToken}`;
      }
      return config;
    },
    (error) => Promise.reject(error)
  );

  const handleLogin = async (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setIsProcessing(true);
    if (!turnstileToken) {
      setLoginMessage(translations[language].captchaError);
      setTimeout(() => setLoginMessage(''), 2000);
      setIsProcessing(false);
      if (turnstileRef.current) {
        turnstileRef.current.reset();
      }
      setTurnstileToken(null);
      return;
    }

    const sanitizedUsername = sanitizeInput(loginUsername);
    const sanitizedPassword = sanitizeInput(loginPassword);

    if (!sanitizedUsername || !sanitizedPassword) {
      setLoginMessage(translations[language].invalidInputError);
      setTimeout(() => setLoginMessage(''), 2000);
      setIsProcessing(false);
      if (turnstileRef.current) {
        turnstileRef.current.reset();
      }
      setTurnstileToken(null);
      return;
    }

    try {
      const response = await api.post('/login', {
        username: sanitizedUsername,
        password: sanitizedPassword,
        turnstileToken,
      });
      console.log('Login response from backend:', response.data);
      if (response.data.success) {
        setLoggedIn(true);
        setUsername(response.data.username);
        setDisplayName(response.data.displayName || response.data.username);
        setIsAdmin(response.data.isAdmin || false);
        setJwtToken(response.data.token);
        localStorage.setItem('jwtToken', response.data.token);
        console.log('Set displayName to:', response.data.displayName);
        setLoginMessage('');
        setLoginUsername('');
        setLoginPassword('');
        setTurnstileToken(null);
      } else {
        setLoginMessage(translations[language].loginError);
        setTimeout(() => setLoginMessage(''), 2000);
        if (response.data.refreshCaptcha && turnstileRef.current) {
          turnstileRef.current.reset();
        }
        setTurnstileToken(null);
      }
    } catch (error) {
      const axiosError = error as AxiosError<ErrorResponse>;
      console.error('Login Error:', axiosError.response ? axiosError.response.data : axiosError.message);
      let errorMessage = translations[language].loginError;
      if (axiosError.response) {
        if (axiosError.response.status === 429) {
          errorMessage = translations[language].rateLimitError;
        } else if (axiosError.response.data?.message === 'Username, password, and CAPTCHA token are required') {
          errorMessage = translations[language].missingFieldsError;
        } else if (axiosError.response.data?.message === 'Invalid CAPTCHA') {
          errorMessage = translations[language].invalidCaptchaError;
        } else if (axiosError.response.data?.message === 'Invalid username or password') {
          errorMessage = translations[language].invalidCredentialsError;
        } else if (axiosError.response.data?.message === 'Server error occurred') {
          errorMessage = translations[language].serverError;
        }
      }
      setLoginMessage(errorMessage);
      setTimeout(() => setLoginMessage(''), 2000);
      if (axiosError.response?.data?.refreshCaptcha && turnstileRef.current) {
        turnstileRef.current.reset();
      }
      setTurnstileToken(null);
    } finally {
      setIsProcessing(false);
    }
  };

  const handleSubmit = async (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    const trimmedPassword = sanitizeInput(password);
    const trimmedConfirmPassword = sanitizeInput(confirmPassword);

    if (!trimmedPassword || !trimmedConfirmPassword || !username) {
      setMessage({ text: translations[language].invalidInputError, type: 'error' });
      setTimeout(() => {
        setMessage(null);
        setPassword('');
        setConfirmPassword('');
      }, 3000);
      return;
    }

    const escapedUsername = username.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    const PASSWORD_REGEX = new RegExp(`^(?!.*${escapedUsername}).{11,}$`);

    const countCategories = (password: string) => {
      let count = 0;
      if (/[A-Z]/.test(password)) count++;
      if (/[a-z]/.test(password)) count++;
      if (/[0-9]/.test(password)) count++;
      if (/[@#$!%*?&]/.test(password)) count++;
      return count;
    };

    if (!PASSWORD_REGEX.test(trimmedPassword) || countCategories(trimmedPassword) < 3) {
      setMessage({ text: translations[language].passwordRequirement, type: 'error' });
      setTimeout(() => {
        setMessage(null);
        setPassword('');
        setConfirmPassword('');
      }, 10000);
      return;
    }

    if (trimmedPassword !== trimmedConfirmPassword) {
      setMessage({ text: translations[language].matchError, type: 'error' });
      setTimeout(() => {
        setMessage(null);
        setPassword('');
        setConfirmPassword('');
      }, 3000);
      return;
    }

    setIsProcessing(true);
    try {
      const adResponse = await api.post('/change-ad-password', {
        newPassword: trimmedPassword,
      });
      if (!adResponse.data.success) {
        throw new Error(adResponse.data.message || translations[language].passwordChangeError);
      }

      const azureResponse = await api.post('/change-azure-password', {
        newPassword: trimmedPassword,
      });

      if (azureResponse.data.success) {
        setMessage({
          text: `${translations[language].successMessage}${displayName}!`,
          type: 'success',
        });
        setPasswordChanged(true);
      } else {
        setMessage({
          text: `${translations[language].azurePendingWarning}${azureResponse.data.message}`,
          type: 'warning',
        });
        setPasswordChanged(true);
      }
      setPassword('');
      setConfirmPassword('');
    } catch (error: any) {
      const axiosError = error as AxiosError<ErrorResponse>;
      console.error('Password Change Error:', axiosError.response ? axiosError.response.data : axiosError.message);
      let errorMessage = translations[language].passwordChangeError;
      if (axiosError.response) {
        if (axiosError.response.status === 401) {
          errorMessage = translations[language].unauthorizedError;
          setTimeout(() => {
            handleLogout();
          }, 2000);
        } else if (axiosError.response.data?.message === 'New password is required') {
          errorMessage = translations[language].missingFieldsError;
        } else if (axiosError.response.data?.message && axiosError.response.data.message.includes('Failed to change')) {
          errorMessage = translations[language].passwordChangeError;
        } else if (axiosError.response.data?.message === 'Server error occurred') {
          errorMessage = translations[language].serverError;
        }
      }
      setMessage({ text: errorMessage, type: 'error' });
      setTimeout(() => {
        setMessage(null);
        setPassword('');
        setConfirmPassword('');
      }, 5000);
    } finally {
      setIsProcessing(false);
    }
  };

  const handleLogout = () => {
    setIsProcessing(true);
    api
      .post('/logout')
      .then(() => {
        setLoggedIn(false);
        setUsername('');
        setDisplayName('');
        setIsAdmin(false);
        setJwtToken(null);
        localStorage.removeItem('jwtToken');
        setMessage(null);
        setPasswordChanged(false);
      })
      .catch((error) => {
        const axiosError = error as AxiosError<ErrorResponse>;
        console.error('Logout Error:', axiosError.response ? axiosError.response.data : axiosError.message);
        let errorMessage = translations[language].logoutError;
        if (axiosError.response) {
          if (axiosError.response.status === 401) {
            errorMessage = translations[language].unauthorizedError;
          } else if (axiosError.response.data?.message === 'Server error occurred') {
            errorMessage = translations[language].serverError;
          }
        }
        setMessage({ text: errorMessage, type: 'error' });
        setTimeout(() => {
          setLoggedIn(false);
          setUsername('');
          setDisplayName('');
          setIsAdmin(false);
          setJwtToken(null);
          localStorage.removeItem('jwtToken');
          setMessage(null);
          setPasswordChanged(false);
        }, 2000);
      })
      .finally(() => {
        setIsProcessing(false);
      });
  };

  const handleGenerateCode = async (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    const sanitizedTargetUsername = sanitizeInput(targetUsername);
    const sanitizedNewSecretCode = sanitizeInput(newSecretCode);

    if (!sanitizedTargetUsername || !sanitizedNewSecretCode) {
      setAdminMessage({ text: translations[language].invalidInputError, type: 'error' });
      setTimeout(() => setAdminMessage(null), 2000);
      return;
    }

    if (sanitizedNewSecretCode.length < 8) {
      setAdminMessage({ text: translations[language].secretCodeTooShort, type: 'error' });
      setTimeout(() => setAdminMessage(null), 2000);
      return;
    }
    if (/\s/.test(sanitizedNewSecretCode)) {
      setAdminMessage({ text: translations[language].secretCodeHasSpaces, type: 'error' });
      setTimeout(() => setAdminMessage(null), 2000);
      return;
    }

    setIsProcessing(true);
    try {
      const response = await api.post('/generate-code', {
        username: sanitizedTargetUsername,
        secretCode: sanitizedNewSecretCode,
      });
      if (response.data.success) {
        setAdminMessage({ text: translations[language].adminSuccessMessage, type: 'success' });
        setTimeout(() => {
          setAdminMessage(null);
          setShowAdminForm(false);
          setTargetUsername('');
          setNewSecretCode('');
        }, 2000);
      } else {
        setAdminMessage({ text: response.data.message || translations[language].adminErrorMessage, type: 'error' });
        setTimeout(() => setAdminMessage(null), 2000);
      }
    } catch (error) {
      const axiosError = error as AxiosError<ErrorResponse>;
      console.error('Generate Code Error:', axiosError.response ? axiosError.response.data : axiosError.message);
      let errorMessage = translations[language].generateCodeError;
      if (axiosError.response) {
        if (axiosError.response.status === 401 || axiosError.response.status === 403) {
          errorMessage = translations[language].unauthorizedError;
          setTimeout(() => {
            handleLogout();
          }, 2000);
        } else if (axiosError.response.data?.message === 'Secret code and username are required') {
          errorMessage = translations[language].missingFieldsError;
        } else if (axiosError.response.data?.message === 'Secret code must be at least 8 characters long') {
          errorMessage = translations[language].secretCodeTooShort;
        } else if (axiosError.response.data?.message === 'Secret code cannot contain spaces') {
          errorMessage = translations[language].secretCodeHasSpaces;
        } else if (axiosError.response.data?.message === 'Failed to generate secret code') {
          errorMessage = translations[language].generateCodeError;
        } else if (axiosError.response.data?.message === 'Server error occurred') {
          errorMessage = translations[language].serverError;
        }
      }
      setAdminMessage({ text: errorMessage, type: 'error' });
      setTimeout(() => setAdminMessage(null), 2000);
    } finally {
      setIsProcessing(false);
    }
  };

  const handleResetPassword = async (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    const sanitizedUsername = sanitizeInput(loginUsername);
    const sanitizedSecretCode = sanitizeInput(secretCode);

    if (!sanitizedUsername || !sanitizedSecretCode) {
      setResetMessage(translations[language].invalidInputError);
      setTimeout(() => setResetMessage(''), 2000);
      return;
    }

    if (sanitizedSecretCode.length < 8) {
      setResetMessage(translations[language].secretCodeTooShort);
      setTimeout(() => setResetMessage(''), 2000);
      return;
    }
    if (/\s/.test(sanitizedSecretCode)) {
      setResetMessage(translations[language].secretCodeHasSpaces);
      setTimeout(() => setResetMessage(''), 2000);
      return;
    }

    setIsProcessing(true);
    try {
      console.log('Attempting reset with:', { username: sanitizedUsername, secretCode: sanitizedSecretCode });
      const response = await axios.post(`${API_URL}/reset-password`, {
        username: sanitizedUsername,
        secretCode: sanitizedSecretCode,
      });
      console.log('Reset response:', response.data);

      if (response.data.success) {
        console.log('Reset successful, showing validation success');
        setShowResetPopup(false);
        setShowValidationSuccess(true);
        setSecretCode('');
        setUsername(response.data.username);
        setDisplayName(response.data.displayName || response.data.username);
        setJwtToken(response.data.token);
        localStorage.setItem('jwtToken', response.data.token);
        setTimeout(() => {
          setShowValidationSuccess(false);
          setLoggedIn(true);
          console.log('Transitioned to password change form');
        }, 3000);
      } else {
        console.log('Reset failed with response:', response.data.message);
        setResetMessage(translations[language].invalidCodeError);
        setTimeout(() => setResetMessage(''), 5000);
      }
    } catch (error) {
      const axiosError = error as AxiosError<ErrorResponse>;
      console.error('Reset Password Error:', axiosError.response ? axiosError.response.data : axiosError.message);
      let errorMessage = translations[language].invalidCodeError;
      if (axiosError.response) {
        if (axiosError.response.status === 429) {
          errorMessage = translations[language].rateLimitError;
        } else if (axiosError.response.data?.message === 'Username and secret code are required') {
          errorMessage = translations[language].missingFieldsError;
        } else if (axiosError.response.data?.message === 'Invalid or expired secret code') {
          errorMessage = translations[language].invalidCredentialsError;
        } else if (axiosError.response.data?.message === 'Server error occurred') {
          errorMessage = translations[language].serverError;
        }
      }
      setResetMessage(errorMessage);
      setTimeout(() => setResetMessage(''), 5000);
    } finally {
      setIsProcessing(false);
    }
  };

  useEffect(() => {
    const storedToken = localStorage.getItem('jwtToken');
    if (storedToken) {
      setJwtToken(storedToken);
    }
  }, []);

  useEffect(() => {
    if (passwordChanged) {
      const timer = setTimeout(() => handleLogout(), 10000);
      return () => clearTimeout(timer);
    }
  }, [passwordChanged]);

  useEffect(() => {
    if (!loggedIn && !showResetPopup && !showValidationSuccess && turnstileRef.current) {
      turnstileRef.current.reset();
      setTurnstileToken(null);
    }
  }, [loggedIn, showResetPopup, showValidationSuccess]);

  return (
    <div className={`App ${isProcessing ? 'processing' : ''}`}>
      <div className="center-container">
        <img src="/logo.png" alt="DragonDoson Logo" style={{ width: '170px' }} />
        <h1>{translations[language].title}</h1>
        {showAdminForm && (
          <div className="admin-form">
            <button
              type="button"
              className="close-button"
              onClick={() => setShowAdminForm(false)}
              disabled={isProcessing}
              aria-label="Close admin form"
            >
              <i className="bi bi-x"></i>
            </button>
            <form onSubmit={handleGenerateCode}>
              <p>{translations[language].adminFormTitle}</p>
              <div>
                <label>{translations[language].usernameLabel}</label>
                <input
                  type="text"
                  value={targetUsername}
                  onChange={(e) => setTargetUsername(e.target.value)}
                  placeholder={translations[language].loginPlaceholder}
                  disabled={isProcessing}
                />
              </div>
              <div>
                <label>{translations[language].secretCodeLabel}</label>
                <input
                  type="text"
                  value={newSecretCode}
                  onChange={(e) => setNewSecretCode(e.target.value)}
                  placeholder={translations[language].secretCodePlaceholder}
                  disabled={isProcessing}
                />
              </div>
              <button type="submit" disabled={isProcessing}>
                {isProcessing ? (
                  <span className="spinner-dots">
                    <span></span>
                    <span></span>
                    <span></span>
                  </span>
                ) : (
                  translations[language].generateButton
                )}
              </button>
              {adminMessage && <p className={adminMessage.type}>{adminMessage.text}</p>}
            </form>
          </div>
        )}
        {!loggedIn ? (
          showValidationSuccess ? (
            <div className="validation-success">
              <p className="success">{translations[language].validationSuccess}</p>
            </div>
          ) : showResetPopup ? (
            <div className="reset-popup">
              <button
                type="button"
                className="close-button"
                onClick={() => {
                  setShowResetPopup(false);
                  setSecretCode('');
                  setResetMessage('');
                }}
                disabled={isProcessing}
                aria-label="Close reset popup"
              >
                <i className="bi bi-x"></i>
              </button>
              <form onSubmit={handleResetPassword}>
                <p>{translations[language].resetInstructions}</p>
                <div>
                  <label>{translations[language].loginUsernameLabel}</label>
                  <input
                    type="text"
                    value={loginUsername}
                    onChange={(e) => setLoginUsername(e.target.value)}
                    placeholder={translations[language].loginPlaceholder}
                    disabled={isProcessing}
                  />
                </div>
                <div>
                  <label>{translations[language].secretCodeLabel}</label>
                  <input
                    type="text"
                    value={secretCode}
                    onChange={(e) => setSecretCode(e.target.value)}
                    placeholder={translations[language].secretCodePlaceholder}
                    disabled={isProcessing}
                  />
                </div>
                <button type="submit" disabled={isProcessing}>
                  {isProcessing ? (
                    <span className="spinner-dots">
                      <span></span>
                      <span></span>
                      <span></span>
                    </span>
                  ) : (
                    translations[language].submitCodeButton
                  )}
                </button>
                {resetMessage && <p className="error">{resetMessage}</p>}
              </form>
            </div>
          ) : (
            <>
              <form onSubmit={handleLogin}>
                <div>
                  <label>{translations[language].loginUsernameLabel}</label>
                  <input
                    type="text"
                    value={loginUsername}
                    onChange={(e) => setLoginUsername(e.target.value)}
                    placeholder={translations[language].loginPlaceholder}
                    disabled={isProcessing}
                  />
                </div>
                <div>
                  <label>{translations[language].loginPasswordLabel}</label>
                  <input
                    type={showLoginPassword ? 'text' : 'password'}
                    value={loginPassword}
                    onChange={(e) => setLoginPassword(e.target.value)}
                    placeholder={translations[language].passwordPlaceholder}
                    disabled={isProcessing}
                  />
                  <button
                    type="button"
                    className="show-password"
                    onClick={() => setShowLoginPassword(!showLoginPassword)}
                    disabled={isProcessing}
                    aria-label={showLoginPassword ? 'Hide password' : 'Show password'}
                    title={showLoginPassword ? 'Hide password' : 'Show password'}
                  >
                    <i className={showLoginPassword ? 'bi bi-eye' : 'bi bi-eye-slash'}></i>
                  </button>
                </div>
                <a
                  href="#"
                  className="forgot-password"
                  onClick={(e) => {
                    e.preventDefault();
                    setShowResetPopup(true);
                  }}
                >
                  {translations[language].forgotPassword}
                </a>
                <button type="submit" disabled={isProcessing}>
                  {isProcessing ? (
                    <span className="spinner-dots">
                      <span></span>
                      <span></span>
                      <span></span>
                    </span>
                  ) : (
                    translations[language].loginButton
                  )}
                </button>
                <p className="error">{loginMessage}</p>
              </form>
              <div className="turnstile-container">
                <Turnstile
                  ref={turnstileRef}
                  siteKey={TURNSTILE_SITE_KEY}
                  onSuccess={(token) => setTurnstileToken(token)}
                  onError={() => setTurnstileToken(null)}
                  onExpire={() => setTurnstileToken(null)}
                  options={{
                    theme: 'light',
                    size: 'flexible',
                  }}
                />
              </div>
            </>
          )
        ) : (
          !showAdminForm && (
            <form onSubmit={handleSubmit}>
              <p className="welcome">
                {translations[language].welcome}
                {displayName}!
              </p>
              {!passwordChanged && (
                <>
                  <div>
                    <label>{translations[language].usernameLabel}</label>
                    <span className="username-display">{username}</span>
                  </div>
                  <div>
                    <label>{translations[language].newPasswordLabel}</label>
                    <input
                      type={showNewPassword ? 'text' : 'password'}
                      value={password}
                      onChange={(e) => setPassword(e.target.value)}
                      placeholder={translations[language].newPasswordPlaceholder}
                      disabled={isProcessing}
                    />
                    <button
                      type="button"
                      className="show-password"
                      onClick={() => setShowNewPassword(!showNewPassword)}
                      disabled={isProcessing}
                      aria-label={showNewPassword ? 'Hide new password' : 'Show new password'}
                      title={showNewPassword ? 'Hide new password' : 'Show new password'}
                    >
                      <i className={showNewPassword ? 'bi bi-eye' : 'bi bi-eye-slash'}></i>
                    </button>
                  </div>
                  <div>
                    <label>{translations[language].confirmLabel}</label>
                    <input
                      type={showConfirmPassword ? 'text' : 'password'}
                      value={confirmPassword}
                      onChange={(e) => setConfirmPassword(e.target.value)}
                      placeholder={translations[language].confirmPlaceholder}
                      disabled={isProcessing}
                    />
                    <button
                      type="button"
                      className="show-password"
                      onClick={() => setShowConfirmPassword(!showConfirmPassword)}
                      disabled={isProcessing}
                      aria-label={showConfirmPassword ? 'Hide confirm password' : 'Show confirm password'}
                      title={showConfirmPassword ? 'Hide confirm password' : 'Show confirm password'}
                    >
                      <i className={showConfirmPassword ? 'bi bi-eye' : 'bi bi-eye-slash'}></i>
                    </button>
                  </div>
                  <button type="submit" disabled={isProcessing}>
                    {isProcessing ? (
                      <span className="spinner-dots">
                        <span></span>
                        <span></span>
                        <span></span>
                      </span>
                    ) : (
                      translations[language].changePasswordButton
                    )}
                  </button>
                </>
              )}
              {message && <p className={message.type}>{message.text}</p>}
            </form>
          )
        )}
      </div>

      <div className="top-right-buttons">
        <button
          className="language-toggle"
          onClick={() => setLanguage(language === 'en' ? 'vi' : 'en')}
          disabled={isProcessing || showAdminForm}
        >
          {language === 'en' ? 'Tiếng Việt' : 'English'}
        </button>
        {loggedIn && isAdmin && (
          <button
            className="admin-button"
            onClick={() => setShowAdminForm(true)}
            disabled={isProcessing || showAdminForm}
          >
            {translations[language].adminButton}
          </button>
        )}
        {loggedIn && (
          <button
            className="logout"
            onClick={handleLogout}
            disabled={isProcessing || showAdminForm}
          >
            {translations[language].logoutButton}
          </button>
        )}
      </div>

      <div className="credit">
        Created by Nguyễn Trần Hưng
      </div>
    </div>
  );
}

export default App;