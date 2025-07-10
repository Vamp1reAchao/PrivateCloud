export function Footer() {
  return (
    <footer className="bg-gray-100 py-4 mt-12" style={{background: 'transparent'}}>
      <div className="container mx-auto text-center text-sm text-muted-foreground">
        &copy; {new Date().getFullYear()} Private Cloud. Все права защищены.
      </div>
    </footer>
  );
}