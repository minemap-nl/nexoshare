export function Footer({ transparent = false }: { transparent?: boolean }) {
    return (
        <footer className={`w-full py-6 text-center text-neutral-500 text-sm mt-auto ${transparent ? '' : 'border-t border-neutral-800 bg-app backdrop-blur-sm'}`}>
            <p className="font-medium tracking-wide">Created by Minemap-nl</p>
        </footer>
    );
}
