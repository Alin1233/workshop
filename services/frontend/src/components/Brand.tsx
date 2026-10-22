// Cette méthode permet d'afficher le logo-anneau et le nom de la marque, en version claire ou sur fond sombre.
export default function Brand({ onDark = false }: { onDark?: boolean }) {
  return (
    <div className={`flex items-center gap-2.5 text-[15px] font-bold tracking-tight ${onDark ? "text-white" : "text-ink"}`}>
      <span className={`grid h-7 w-7 place-items-center rounded-lg ${onDark ? "bg-white/10" : "bg-ink"}`}>
        <span className="h-2.75 w-2.75 rounded-full border-[2.5px] border-mint" />
      </span>
      Resilience Pay
    </div>
  );
}
