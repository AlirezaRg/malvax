import { LoginForm } from "@/components/LoginForm";

export default function Login() {
  return (
    <div className="max-w-sm space-y-4">
      <h1 className="text-lg text-zinc-100">Sign in</h1>
      <p className="text-zinc-500 text-xs">
        Laboratory accounts only. Accounts are created by an administrator.
      </p>
      <LoginForm />
    </div>
  );
}
