"""
collision.py - herbruikbare botsing-zoeker voor AFGEKAPTE hashes.

Vind twee verschillende invoeren met dezelfde (korte) fingerprint. Gebruikt de
Floyd/rho-methode: weinig geheugen, haalbaar tot ~48-56 bits afkaplengte.

Importeer en gebruik:
    from collision import find_collision
    i, j = find_collision(fp_of_index)
waarbij fp_of_index(i) -> int  de afgekapte fingerprint is van 'invoer nummer i'.

Zie solve_template.py voor een ingevuld voorbeeld.
"""

def find_collision(fp_of_index, start=1):
    """
    fp_of_index(x: int) -> int   : de afgekapte fingerprint (als geheel getal)
                                    van de x-de kandidaat-invoer.
    Geeft twee verschillende indices (i, j) met fp_of_index(i)==fp_of_index(j).
    """
    f = fp_of_index
    # fase 1: vind een cyclus (schildpad t, haas h)
    t = f(start); h = f(f(start))
    while t != h:
        t = f(t); h = f(f(h))
    # fase 2: zoek het begin van de cyclus; pt en ph zijn dan de twee botsers
    t = start; pt = ph = None
    while t != h:
        pt, ph = t, h
        t = f(t); h = f(h)
    if pt is None or pt == ph:
        # zeldzaam randgeval -> probeer een ander startpunt
        return find_collision(fp_of_index, start + 1)
    return pt, ph