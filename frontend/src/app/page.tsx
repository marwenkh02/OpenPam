import Link from 'next/link';

export default function Home() {
  return (
    <main className="flex flex-col items-center justify-center min-h-screen p-8 bg-gradient-to-br from-blue-50 to-indigo-100">
      <div className="text-center mb-12">
        <h1 className="text-5xl font-bold text-gray-800 mb-4">OpenPAM</h1>
        <p className="text-xl text-gray-600 max-w-2xl">
          Lightweight Privileged Access Management Platform for small/medium businesses and DevOps teams.
        </p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-8 max-w-4xl w-full">
        <div className="bg-white rounded-lg shadow-lg p-6 flex flex-col">
          <h2 className="text-2xl font-semibold text-gray-800 mb-4">Secure Credential Management</h2>
          <p className="text-gray-600 mb-6 flex-grow">
            Store and manage privileged credentials securely with our encrypted vault and role-based access control.
          </p>
          <ul className="text-gray-600 mb-6 space-y-2">
            <li className="flex items-center">
              <span className="text-green-500 mr-2">✓</span> Just-in-Time Access
            </li>
            <li className="flex items-center">
              <span className="text-green-500 mr-2">✓</span> Session Recording
            </li>
            <li className="flex items-center">
              <span className="text-green-500 mr-2">✓</span> Auto-Rotation
            </li>
          </ul>
        </div>

        <div className="bg-white rounded-lg shadow-lg p-6 flex flex-col">
          <h2 className="text-2xl font-semibold text-gray-800 mb-4">Get Started</h2>
          <p className="text-gray-600 mb-6 flex-grow">
            Create an account to start managing your privileged access or login if you already have an account.
          </p>
          
          <div className="space-y-4">
            <Link 
              href="/login"
              className="block w-full bg-blue-600 hover:bg-blue-700 text-white font-semibold py-3 px-4 rounded-lg text-center transition duration-200"
            >
              Login to Your Account
            </Link>
            
            <Link 
              href="/signup"
              className="block w-full bg-white hover:bg-gray-50 text-blue-600 font-semibold py-3 px-4 rounded-lg border border-blue-600 text-center transition duration-200"
            >
              Create New Account
            </Link>
          </div>
        </div>
      </div>

      <footer className="mt-16 text-center text-gray-500">
        <p>© {new Date().getFullYear()} OpenPAM. All rights reserved.</p>
      </footer>
    </main>
  );
}