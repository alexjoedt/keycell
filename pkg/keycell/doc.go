// Package keycell ist der einzige Client-Pfad zu einem laufenden keycelld.
//
// Ein Secret besteht aus Name, Kind, Attributes und Value. Der Value ist
// der geheime Payload und kommt als [*Value] an: Expose liefert die Bytes,
// Destroy nullt sie. Alles andere (Name, Kind, Attributes) ist nicht geheim.
//
// Der Common Case sind drei Zeilen:
//
//	s, err := client.Get(ctx, "github/token")
//	defer s.Value.Destroy()
//	use(s.Value.Expose())
//
// Jeder Aufruf öffnet eine eigene Verbindung zum Socket; ein Client ist
// deshalb billig, zustandslos und nebenläufig nutzbar.
package keycell
