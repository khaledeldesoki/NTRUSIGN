from KeyGenerator import KeyPair
from Polynomial import Polynomial
from multiprocessing import Pool, cpu_count
import hashlib
import numpy as np

##Implements Signing and Verifying according to the NTRU-Sign algorithm

try:
    nproc = 2 * cpu_count()
except NotImplementedError:
    nproc = 1

def pbar(max, min, curr, r):##==============>
    """
    Print a progress bar and with value curr between max and min
    """
    percentage = int(30*(max - curr)/(max - min))
    s = "("
    for i in range(percentage):
        s += "="
    s += ">"
    while len(s) < 30:
        s += " "
    s += ") " + str(int(percentage*100/30)) + "% " + str(r) + " " + str(curr) + "      "
    print(s, end="\r")
#__________________________________________________
###Hash the document D and randomness r into a polynomial m0​.
def H(s: bytes, N: int):
    """
    Convert the byte string to a polynomial
    using its sha1.
    """
    h = hashlib.sha1()   # 1. Initialize SHA-1 hasher
    i = 0
    m = ""               # 3. Hex digest accumulator -> collect hex characters
    while len(m) < N:
        h.update(s+str(i).encode("ascii"))
        m += h.hexdigest() # Append 40 hex characters
    
    p = Polynomial(N=N)  # 5. Map hex string to polynomial coefficients
    for i in range(len(m)): 
        p.coeff[i % N] += ord(m[i])
    return p
#___________________________________________________


def NTRUNorm(P, Q, mod=(0, 0)):
# 1. Extract raw coefficient arrays
    Pc, Qc = P.coeff, Q.coeff
# 2. Apply modular reduction if specified
    if mod[0] != 0 and mod[0]:
        q = abs(mod[0])
        Pc = Pc % q # Reduce each entry of P modulo q
    if mod[1] != 0 and mod[1]:
        q = abs(mod[1])
        Qc = Qc % q

    # 3. Compute centered norm for P: sqrt(Σ(Pc_i^2) - (Σ Pc_i)^2 / N)
    res_p = np.sqrt(np.sum(np.square(Pc)) - np.square(np.sum(Pc))/len(Pc))
    # 4. Compute centered norm for Q 
    res_q = np.sqrt(np.sum(np.square(Qc)) - np.square(np.sum(Qc))/len(Qc))
    return np.sqrt(res_p**2 + res_q**2)
#_________________________________________________________________________

def signing_worker(params):
    """
    Sign the document D with the key k and boundary N_bound.
    """
    k, D, N_bound, r = params
    N = k.N
    q = k.q
    max_b = 700
    l_b = float('inf')

    # Prepare accumulators
    # s will collect the final signature vector
    s = Polynomial(N=N)    # starts as [0,0]
    x = Polynomial(N=N)    # temp coefficient vector
    y = Polynomial(N=N)    # temp coefficient vector

    # Rejection-sampling loop:
    # keep trying new r until we find a short enough s

    while True:
        i = k.B

        # 1) Hash the document || r into a polynomial m0
        m0 = H(D+r.to_bytes(10, 'big'), k.N)
        m = m0
        while i >= 1:

            # Perturb the point using the private lattice
            #star_multiply is a polynomial multiplication under convolution modulo.
            
            #compute the “coordinates” x and y of the lattice point closest to m 
            x.coeff = np.fix((m.star_multiply(k.priv[1][i])*(-1/q)).coeff)


            y.coeff = np.fix((m.star_multiply(k.priv[0][i])*(1/q)).coeff)

            #Approximate m using a lattice vector si​
            si = x.star_multiply(k.priv[0][i]) + y.star_multiply(k.priv[1][i])

            
            #trapdoor m1​=s1​⋆(T1​−T0​)modq.
            m = si.star_multiply(k.priv[2][i] - k.priv[2][i-1]).mod(q)
            s = s + si
            i -= 1

        # Sign the perturbed point using the public lattice

        x.coeff = np.fix((m0.star_multiply(k.priv[1][0])*(-1/q)).coeff)
        y.coeff = np.fix((m0.star_multiply(k.priv[0][0])*(1/q)).coeff)
        s0 = x.star_multiply(k.priv[0][0]) + y.star_multiply(k.priv[1][0])
        s = s + s0

        # Check the signature
        # Rejection sampling over different hash-seeds r guarantees that 
        # the final s is both valid and “short”

        b = NTRUNorm(s, s.star_multiply(k.priv[2][0]) - m0, (0, q))
        if b < N_bound:
            break
        elif b < l_b:
            l_b = b
        r = r + nproc
        pbar(max_b, N_bound, l_b, r)
        s.coeff = np.zeros(N)
        x.coeff = np.zeros(N)
        y.coeff = np.zeros(N)

    return (D, r, s)


def Signing(k: KeyPair, D, N_bound):
    params = [(k, D, N_bound, i) for i in range(nproc)]
    with Pool(nproc) as p:
        print(f"Launching {nproc} process")
        for res in p.imap_unordered(signing_worker, params, chunksize=1):
            (D, r, s) = res
            break
    return (D, r, s)


def Verifying(D, r, s, N_bound, k: KeyPair):
    """
    Verify if the document D was signed by the
    key k and boundary N_bound.
    """
    m = H(D+r.to_bytes(10, 'big'), k.N)
    b = NTRUNorm(s, s.star_multiply(k.pub) - m, (0, k.q))
    if b < N_bound:
        return True
    return False


def export_signature(r, s, N_Bound, prints: bool):
    """
    Export the signature to a string.
    If prints is True, the signature will also be printed
    """
    sig = "-----BEGIN NTRU SIGNATURE BLOCK-----\n"
    for c in s.coeff:
        sig += str(c) + "|"
    sig = sig[:-1]
    sig += "\n=="
    sig += str(r)
    sig += "\n-----END NTRU SIGNATURE BLOCK-----\n"

    if prints:
        print(sig)
    return sig


def import_signature(sig: str):
    """
    Import the signature from a string.
    """
    c = 0
    while sig[c] != '\n':
        c += 1
    c += 1
    coeff = []
    nb = ""
    while sig[c] != '\n':
        if sig[c] == "|":
            coeff += [int(nb)]
            nb = ""
        else:
            nb += sig[c]
        c += 1
    coeff += [int(nb)]
    s = Polynomial(N=len(coeff))
    s.coeff = np.array(coeff)
    nb = ""
    c += 3
    while sig[c] != '\n':
        nb += sig[c]
        c += 1
    r = int(nb)

    return r, s


if __name__ == "__main__":
    infile = open("Alice.pdf", "rb")
    data = infile.read()

    # Load key
    k = KeyPair()
    infile = open("key_pub.asc", "r")
    s = infile.read()
    infile = open("key_priv.asc", "r")
    s_priv = infile.read()
    # k.import_pub(s)
    k.import_priv(s_priv)
    """
    infile = open("Alice.ntru", "r")
    signature_str = infile.read()

    sig = import_signature(signature_str)
    print("Keys imported")
    Verifying(data, sig[0], sig[1], sig[2], k)
    """

    sdoc = Signing(k=k, D=data, N_bound=555)
    export_signature(sdoc[1], sdoc[2], 555, True)
