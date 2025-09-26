// Tailwind CSS Configuration
tailwind.config = {
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        primary: '#00D1FF', // Changed to futuristic cyan
        secondary: '#7E22CE',
        accent: '#FF0080',
        bgcard: 'rgba(17, 25, 40, 0.75)', // Darker glass effect
        borderGlass: 'rgba(255, 255, 255, 0.1)',
        darkbg: '#0F172A',
      },
      fontFamily: {
        sans: ['Inter', 'ui-sans-serif', 'system-ui'],
        mono: ['JetBrains Mono', 'monospace'], // More futuristic monospace
      },
      backdropBlur: {
        xs: '4px',
        sm: '8px',
      },
      animation: {
        'pulse-slow': 'pulse 3s cubic-bezier(0.4, 0, 0.6, 1) infinite',
        'float': 'float 6s ease-in-out infinite',
        'glow': 'glow 2s ease-in-out infinite alternate',
      },
      keyframes: {
        float: {
          '0%, 100%': { transform: 'translateY(0)' },
          '50%': { transform: 'translateY(-10px)' },
        },
        glow: {
          '0%': { boxShadow: '0 0 5px #00D1FF, 0 0 10px #00D1FF, 0 0 15px #00D1FF' },
          '100%': { boxShadow: '0 0 10px #00D1FF, 0 0 20px #00D1FF, 0 0 30px #00D1FF' },
        }
      }
    },
  },
};