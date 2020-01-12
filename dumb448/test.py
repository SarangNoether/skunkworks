# Test suite for dumb448

from dumb448 import *
import unittest

# Scalar class
class TestScalar(unittest.TestCase):
    def test_init(self):
        # Test construction using x = 1
        s = Scalar(int(1))
        self.assertEqual(s,Scalar(long(1)))
        self.assertEqual(s,Scalar('010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000'))
        self.assertEqual(s.x,int(1))
        self.assertEqual(s.x,long(1))

        # Test construction using x = l = 0
        s = Scalar(int(l))
        self.assertEqual(s,Scalar(long(l)))
        self.assertEqual(s,Scalar('000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000'))
        self.assertEqual(s.x,int(0))
        self.assertEqual(s.x,long(0))

        # Test invalid constructions
        with self.assertRaises(TypeError):
            Scalar('invalid')
        with self.assertRaises(TypeError):
            Scalar(None)

    def test_invert(self):
        # Test nonzero inversion
        self.assertEqual(Scalar(1).invert(),Scalar(1))
        self.assertEqual(Scalar(1).invert(allow_zero=True),Scalar(1))
        self.assertEqual(Scalar(2).invert()*Scalar(2),Scalar(1))
        self.assertEqual(Scalar(2).invert(allow_zero=True)*Scalar(2),Scalar(1))
        
        # Test zero inversion
        self.assertEqual(Scalar(0).invert(allow_zero=True),Scalar(0))
        with self.assertRaises(ZeroDivisionError):
            Scalar(0).invert()

    def test_add(self):
        # Test valid addition
        self.assertEqual(Scalar(0) + Scalar(1),Scalar(1))
        self.assertEqual(Scalar(1) + Scalar(1),Scalar(2))
        self.assertEqual(Scalar(l - 1) + Scalar(1),Scalar(0))
        self.assertEqual(Scalar(1) + Scalar(-1),Scalar(0))

        # Test invalid addition
        with self.assertRaises(TypeError):
            Scalar(1) + 1
        with self.assertRaises(TypeError):
            1 + Scalar(1)
        with self.assertRaises(TypeError):
            Scalar(1) + None

    def test_sub(self):
        # Test valid subtraction
        self.assertEqual(Scalar(0) - Scalar(1),Scalar(-1))
        self.assertEqual(Scalar(1) - Scalar(0),Scalar(1))
        self.assertEqual(Scalar(2) - Scalar(1),Scalar(1))
        self.assertEqual(Scalar(1) - Scalar(-1),Scalar(2))

        # Test invalid subtraction
        with self.assertRaises(TypeError):
            Scalar(1) - 1
        with self.assertRaises(TypeError):
            1 - Scalar(1)
        with self.assertRaises(TypeError):
            Scalar(1) - None

    def test_mul(self):
        # Test Scalar-Scalar multiplication
        self.assertEqual(Scalar(1)*Scalar(1),Scalar(1))
        self.assertEqual(Scalar(1)*Scalar(0),Scalar(0))
        self.assertEqual(Scalar(2)*Scalar(1),Scalar(2))
        self.assertEqual(Scalar(-2)*Scalar(1),Scalar(-2))

        # Test Scalar-int multiplication
        self.assertEqual(Scalar(1)*1,Scalar(1))
        self.assertEqual(Scalar(1)*0,Scalar(0))
        self.assertEqual(Scalar(2)*1,Scalar(2))
        self.assertEqual(Scalar(-2)*1,Scalar(-2))
        self.assertEqual(Scalar(2)*-1,Scalar(-2))

        # Test int-Scalar multiplication
        self.assertEqual(1*Scalar(1),Scalar(1))
        self.assertEqual(0*Scalar(1),Scalar(0))
        self.assertEqual(1*Scalar(2),Scalar(2))
        self.assertEqual(1*Scalar(-2),Scalar(-2))
        self.assertEqual(-1*Scalar(2),Scalar(-2))

        # Test invalid multiplication
        with self.assertRaises(TypeError):
            Scalar(1)*None
        with self.assertRaises(TypeError):
            None*Scalar(1)

    def test_div(self):
        # Test valid division
        self.assertEqual(Scalar(1)/Scalar(1),Scalar(1))
        self.assertEqual(Scalar(0)/Scalar(1),Scalar(0))
        self.assertEqual(Scalar(1)/Scalar(2),Scalar(0))
        self.assertEqual(Scalar(2)/Scalar(2),Scalar(1))

        self.assertEqual(Scalar(1)/1,Scalar(1))
        self.assertEqual(Scalar(0)/1,Scalar(0))
        self.assertEqual(Scalar(1)/2,Scalar(0))
        self.assertEqual(Scalar(2)/2,Scalar(1))

        # Test invalid division
        with self.assertRaises(TypeError):
            Scalar(1)/None
        with self.assertRaises(ZeroDivisionError):
            Scalar(1)/Scalar(0)
        with self.assertRaises(TypeError):
            Scalar(1)/-1

    def test_pow(self):
        # Test valid exponentiation
        self.assertEqual(Scalar(2)**0,Scalar(1))
        self.assertEqual(Scalar(2)**1,Scalar(2))
        self.assertEqual(Scalar(2)**2,Scalar(4))

        # Test invalid exponentiation
        with self.assertRaises(TypeError):
            Scalar(2)**-1
        with self.assertRaises(TypeError):
            Scalar(2)**Scalar(1)
        with self.assertRaises(TypeError):
            Scalar(2)**None

    def test_eq(self):
        # Test valid equality
        self.assertEqual(Scalar(1),Scalar(1))
        self.assertEqual(Scalar(l),Scalar(0))
        self.assertEqual(Scalar(l-1),Scalar(-1))

        # Test invalid equality
        with self.assertRaises(TypeError):
            Scalar(0) == 0
        with self.assertRaises(TypeError):
            0 == Scalar(0)
        with self.assertRaises(TypeError):
            Scalar(0) == None
        with self.assertRaises(TypeError):
            None == Scalar(0)

    def test_ne(self):
        # Test valid inequality
        self.assertNotEqual(Scalar(1),Scalar(0))
        self.assertNotEqual(Scalar(0),Scalar(1))
        self.assertNotEqual(Scalar(-1),Scalar(1))

        # Test invalid inequality
        with self.assertRaises(TypeError):
            Scalar(0) != 0
        with self.assertRaises(TypeError):
            0 != Scalar(0)
        with self.assertRaises(TypeError):
            Scalar(0) != None
        with self.assertRaises(TypeError):
            None != Scalar(0)

    def test_lt(self):
        # Test correct less-than
        self.assertTrue(Scalar(0) < Scalar(1))
        self.assertTrue(Scalar(0) < Scalar(l-1))
        self.assertTrue(Scalar(1) < Scalar(l-1))
        self.assertTrue(Scalar(0) < Scalar(l+1))

        # Test incorrect less-than
        self.assertFalse(Scalar(0) < Scalar(0))
        self.assertFalse(Scalar(0) < Scalar(l))
        self.assertFalse(Scalar(1) < Scalar(0))

        # Test invalid less-than
        with self.assertRaises(TypeError):
            Scalar(0) < 1
        with self.assertRaises(TypeError):
            1 < Scalar(0)
        with self.assertRaises(TypeError):
            Scalar(0) < None
        with self.assertRaises(TypeError):
            None < Scalar(0)

    def test_gt(self):
        # Test correct greater-than
        self.assertTrue(Scalar(1) > Scalar(0))
        self.assertTrue(Scalar(l-1) > Scalar(0))
        self.assertTrue(Scalar(l-1) > Scalar(1))
        self.assertTrue(Scalar(l+1) > Scalar(0))

        # Test incorrect greater-than
        self.assertFalse(Scalar(0) > Scalar(0))
        self.assertFalse(Scalar(l) > Scalar(0))
        self.assertFalse(Scalar(0) > Scalar(1))

        # Test invalid greater-than
        with self.assertRaises(TypeError):
            Scalar(0) > 1
        with self.assertRaises(TypeError):
            1 > Scalar(0)
        with self.assertRaises(TypeError):
            Scalar(0) > None
        with self.assertRaises(TypeError):
            None > Scalar(0)

    def test_le(self):
        # Test correct less-than-or-equal
        self.assertTrue(Scalar(0) <= Scalar(0))
        self.assertTrue(Scalar(0) <= Scalar(1))
        self.assertTrue(Scalar(0) <= Scalar(l-1))
        self.assertTrue(Scalar(1) <= Scalar(l-1))
        self.assertTrue(Scalar(0) <= Scalar(l+1))

        # Test incorrect less-than-or-equal
        self.assertFalse(Scalar(1) <= Scalar(0))

        # Test invalid less-than-or-equal
        with self.assertRaises(TypeError):
            Scalar(0) <= 1
        with self.assertRaises(TypeError):
            1 <= Scalar(0)
        with self.assertRaises(TypeError):
            Scalar(0) <= None
        with self.assertRaises(TypeError):
            None <= Scalar(0)

    def test_ge(self):
        # Test correct greater-than-or-equal
        self.assertTrue(Scalar(0) >= Scalar(0))
        self.assertTrue(Scalar(1) >= Scalar(0))
        self.assertTrue(Scalar(l-1) >= Scalar(0))
        self.assertTrue(Scalar(l-1) >= Scalar(1))
        self.assertTrue(Scalar(l+1) >= Scalar(0))

        # Test incorrect greater-than-or-equal
        self.assertFalse(Scalar(0) >= Scalar(1))

        # Test invalid greater-than-or-equal
        with self.assertRaises(TypeError):
            Scalar(0) >= 1
        with self.assertRaises(TypeError):
            1 >= Scalar(0)
        with self.assertRaises(TypeError):
            Scalar(0) >= None
        with self.assertRaises(TypeError):
            None >= Scalar(0)

    def test_repr(self):
        # Test known representations
        self.assertEqual(repr(Scalar(0)),'000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000')
        self.assertEqual(str(Scalar(0)),'000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000')
        self.assertEqual(repr(Scalar(1)),'010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000')
        self.assertEqual(str(Scalar(1)),'010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000')

        eight = Scalar('080000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000')
        inv_8 = Scalar('182b17ab9b792b3695799b9887f9e3141ae2450d0e49b11a7256feadffffffffffffffffffffffffffffffffffffffffffffffffffffff2700')
        self.assertEqual(eight*inv_8,Scalar(1))

    def test_int(self):
        # Test ingeger reconstruction
        self.assertEqual(int(Scalar(0)),0)
        self.assertEqual(int(Scalar(l)),0)
        self.assertEqual(int(Scalar(1)),1)
        self.assertEqual(int(Scalar(-1)),l-1)

    def test_mod(self):
        # Test valid modulus
        self.assertEqual(Scalar(0) % 2, Scalar(0))
        self.assertEqual(Scalar(1) % 2, Scalar(1))
        self.assertEqual(Scalar(2) % 2, Scalar(0))
        self.assertEqual(Scalar(0) % Scalar(2), Scalar(0))
        self.assertEqual(Scalar(1) % Scalar(2), Scalar(1))
        self.assertEqual(Scalar(2) % Scalar(2), Scalar(0))

        # Test invalid modulus
        with self.assertRaises(TypeError):
            Scalar(0) % 0
        with self.assertRaises(TypeError):
            0 % Scalar(1)
        with self.assertRaises(TypeError):
            Scalar(0) % -1
        with self.assertRaises(TypeError):
            Scalar(0) % Scalar(0)
        with self.assertRaises(TypeError):
            Scalar(0) % None
        with self.assertRaises(TypeError):
            None % Scalar(0)

    def test_neg(self):
        # Test negation
        self.assertEqual(-Scalar(0),Scalar(-0))
        self.assertEqual(-Scalar(0),Scalar(0))
        self.assertEqual(-Scalar(1),Scalar(-1))
        self.assertEqual(-Scalar(1),Scalar(l-1))

# Point class
class TestPoint(unittest.TestCase):
    def test_init(self):
        # Test construction with known hex representations
        self.assertEqual(Point('14fa30f25b790898adc8d74e2c13bdfdc4397ce61cffd33ad7c2a0051e9c78874098a36c7373ea4b62c7c9563720768824bcb66e71463f6900'),G)
        self.assertEqual(Point('010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000'),Z)

        # Test construction of zero with coordinates
        self.assertEqual(Point(0,1),Z)
        self.assertEqual(Point(int(0),int(1)),Z)
        self.assertEqual(Point(long(0),long(1)),Z)

        # Test invalid constructions
        with self.assertRaises(TypeError):
            Point('invalid')
        with self.assertRaises(TypeError):
            Point(None)
        with self.assertRaises(ValueError):
            Point(0,0)
        with self.assertRaises(TypeError):
            Point(0,None)
        with self.assertRaises(TypeError):
            Point(None,0)
        with self.assertRaises(TypeError):
            Point(0)

    def test_eq(self):
        # Test valid equality
        self.assertEqual(Z,Z)
        self.assertEqual(G,G)

        # Test invalid equality
        with self.assertRaises(TypeError):
            G == None
        with self.assertRaises(TypeError):
            None == G

    def test_ne(self):
        # Test valid inequality
        self.assertNotEqual(Z,G)

        # Test invalid inequality
        with self.assertRaises(TypeError):
            G != None
        with self.assertRaises(TypeError):
            None != G

    def test_add(self):
        # Test valid addition
        self.assertEqual(G + Z,G)
        self.assertEqual(Z + G,G)
        self.assertEqual(Z + Z,Z)

        # Test invalid addition
        with self.assertRaises(TypeError):
            G + None
        with self.assertRaises(TypeError):
            None + G

    def test_sub(self):
        # Test valid subtraction
        self.assertEqual(G - Z,G)
        self.assertEqual(G - G,Z)
        self.assertEqual(Z - Z,Z)

        # Test invalid subtraction
        with self.assertRaises(TypeError):
            G - None
        with self.assertRaises(TypeError):
            None - G

    def test_mul(self):
        # Test Point-Scalar multiplication
        self.assertEqual(G*Scalar(1),G)
        self.assertEqual(G*Scalar(2),G + G)
        self.assertEqual(G*Scalar(0),Z)
        self.assertEqual(Z*Scalar(1),Z)

        # Test Scalar-Point multiplication
        self.assertEqual(Scalar(1)*G,G)
        self.assertEqual(Scalar(2)*G,G+G)
        self.assertEqual(Scalar(0)*G,Z)
        self.assertEqual(Scalar(1)*Z,Z)

        # Test invalid multiplication
        with self.assertRaises(TypeError):
            G*None
        with self.assertRaises(TypeError):
            None*G

    def test_repr(self):
        # Test known representations
        self.assertEqual(repr(G),'14fa30f25b790898adc8d74e2c13bdfdc4397ce61cffd33ad7c2a0051e9c78874098a36c7373ea4b62c7c9563720768824bcb66e71463f6900')
        self.assertEqual(str(G),'14fa30f25b790898adc8d74e2c13bdfdc4397ce61cffd33ad7c2a0051e9c78874098a36c7373ea4b62c7c9563720768824bcb66e71463f6900')
        self.assertEqual(repr(Z),'010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000')
        self.assertEqual(str(Z),'010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000')

    def test_neg(self):
        # Test negation
        self.assertEqual(-G,Z-G)
        self.assertEqual(-G+G,Z)
        self.assertEqual(-Z,Z)


# PointVector class
class TestPointVector(unittest.TestCase):
    def test_init(self):
        # Test valid construction
        self.assertEqual(PointVector(),PointVector([]))
        self.assertEqual(PointVector(),PointVector(None))
        PointVector([Z])
        PointVector([Z,G])
        
        # Test invalid construction
        with self.assertRaises(TypeError):
            PointVector(1)
        with self.assertRaises(TypeError):
            PointVector([Z,None])

    def test_eq(self):
        # Test valid equality
        self.assertEqual(PointVector([Z]),PointVector([Z]))
        self.assertEqual(PointVector([Z,G]),PointVector([Z,G]))

        # Test invalid equality
        with self.assertRaises(TypeError):
            PointVector() == None
        with self.assertRaises(TypeError):
            None == PointVector()

    def test_ne(self):
        # Test valid inequality
        self.assertNotEqual(PointVector(),PointVector([Z]))
        self.assertNotEqual(PointVector([Z]),PointVector([G]))
        self.assertNotEqual(PointVector([G]),PointVector([G,G]))

        # Test invalid inequality
        with self.assertRaises(TypeError):
            PointVector() != None
        with self.assertRaises(TypeError):
            None != PointVector()

    def test_add(self):
        # Test valid addition
        self.assertEqual(PointVector([G,G+G,G+G+G]) + PointVector([Z,Z,Z]),PointVector([G,G+G,G+G+G]))
        self.assertEqual(PointVector([G,G,G]) + PointVector([Z,G,G+G]),PointVector([G,G+G,G+G+G]))

        # Test invalid addition
        with self.assertRaises(TypeError):
            PointVector([G]) + PointVector()
        with self.assertRaises(TypeError):
            PointVector([G]) + PointVector([G,G])
        with self.assertRaises(TypeError):
            PointVector([G]) + None
        with self.assertRaises(TypeError):
            None + PointVector([G])

    def test_sub(self):
        # Test valid subtraction
        self.assertEqual(PointVector([G,G+G,G+G+G]) - PointVector([Z,Z,Z]),PointVector([G,G+G,G+G+G]))
        self.assertEqual(PointVector([G,G+G,G+G+G]) - PointVector([Z,G,G+G]),PointVector([G,G,G]))
        self.assertEqual(PointVector([G,G+G,G+G+G]) - PointVector([G,G+G,G+G+G]),PointVector([Z,Z,Z]))

        # Test invalid subtraction
        with self.assertRaises(TypeError):
            PointVector([G]) - PointVector()
        with self.assertRaises(TypeError):
            PointVector([G]) - PointVector([G,G])
        with self.assertRaises(TypeError):
            PointVector([G]) - None
        with self.assertRaises(TypeError):
            None - PointVector([G])

    def test_mul(self):
        # Test PointVector-Scalar multiplication
        self.assertEqual(PointVector([G,G,G])*Scalar(2),PointVector([Scalar(2)*G,Scalar(2)*G,Scalar(2)*G]))
        self.assertEqual(PointVector([Z,G,G+G])*Scalar(0),PointVector([Z,Z,Z]))

        # Test Scalar-PointVector multiplication
        self.assertEqual(Scalar(2)*PointVector([G,G,G]),PointVector([Scalar(2)*G,Scalar(2)*G,Scalar(2)*G]))
        self.assertEqual(Scalar(0)*PointVector([Z,G,G+G]),PointVector([Z,Z,Z]))
        
        # Test PointVector-ScalarVector multiplication
        self.assertEqual(PointVector([Z,Z,Z])*ScalarVector([Scalar(1),Scalar(2),Scalar(3)]),PointVector([Z,Z,Z]))
        self.assertEqual(PointVector([Z,G,G+G])*ScalarVector([Scalar(1),Scalar(2),Scalar(3)]),PointVector([Z,Scalar(2)*G,Scalar(6)*G]))

        # Test ScalarVector-PointVector multiplication
        self.assertEqual(ScalarVector([Scalar(1),Scalar(2),Scalar(3)])*PointVector([Z,Z,Z]),PointVector([Z,Z,Z]))
        self.assertEqual(ScalarVector([Scalar(1),Scalar(2),Scalar(3)])*PointVector([Z,G,G+G]),PointVector([Z,Scalar(2)*G,Scalar(6)*G]))

        # Test invalid multiplication
        with self.assertRaises(TypeError):
            PointVector([G,G,G])*None
        with self.assertRaises(TypeError):
            None*PointVector([G,G,G])
        with self.assertRaises(TypeError):
            PointVector([Z,Z,Z])*ScalarVector([Scalar(1),Scalar(2)])
        with self.assertRaises(TypeError):
            ScalarVector([Scalar(1),Scalar(2)])*PointVector([Z,Z,Z])

    def test_pow(self):
        # Test valid multiscalar multiplication
        self.assertEqual(PointVector([G,G+G])**ScalarVector([Scalar(1),Scalar(2)]),Scalar(5)*G)
        self.assertEqual(PointVector()**ScalarVector(),Z)

        # Test invalid multiscalar multiplication
        with self.assertRaises(TypeError):
            PointVector()**None
        with self.assertRaises(TypeError):
            PointVector([Z])**ScalarVector()

    def test_len(self):
        # Test length
        self.assertEqual(len(PointVector()),0)
        self.assertEqual(len(PointVector([G])),1)
        self.assertEqual(len(PointVector([Z,G])),2)

    def test_getitem(self):
        # Test valid gets
        P = PointVector([Z,G,G+G])
        self.assertEqual(P[0],Z)
        self.assertEqual(P[1],G)
        self.assertEqual(P[2],G+G)
        self.assertEqual(P[0:-1],PointVector([Z,G]))

        # Test invalid get
        with self.assertRaises(IndexError):
            P[3]

    def test_setitem(self):
        # Test valid sets
        P = PointVector([Z,G,G+G])
        P[0] = G
        self.assertEqual(P,PointVector([G,G,G+G]))

        # Test invalid sets
        with self.assertRaises(IndexError):
            P[3] = Z
        with self.assertRaises(TypeError):
            P[0] = None

    def test_append(self):
        # Test valid append
        P = PointVector()
        P.append(Z)
        self.assertEqual(P,PointVector([Z]))
        P.append(G)
        self.assertEqual(P,PointVector([Z,G]))

        # Test invalid append
        with self.assertRaises(TypeError):
            P.append(None)

    def test_extend(self):
        # Test valid extend
        P = PointVector()
        P.extend(PointVector())
        self.assertEqual(P,PointVector())
        P.extend(PointVector([Z,G]))
        self.assertEqual(P,PointVector([Z,G]))
        P.extend(PointVector([G+G]))
        self.assertEqual(P,PointVector([Z,G,G+G]))

        # Test invalid extend
        with self.assertRaises(TypeError):
            P.extend(None)
        with self.assertRaises(TypeError):
            P.extend(Z)
        with self.assertRaises(TypeError):
            P.extend([Z])

    def test_repr(self):
        # Test known representation
        self.assertEqual(repr(PointVector([Z,G])),'[010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000, 14fa30f25b790898adc8d74e2c13bdfdc4397ce61cffd33ad7c2a0051e9c78874098a36c7373ea4b62c7c9563720768824bcb66e71463f6900]')
        self.assertEqual(str(PointVector([Z,G])),'[010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000, 14fa30f25b790898adc8d74e2c13bdfdc4397ce61cffd33ad7c2a0051e9c78874098a36c7373ea4b62c7c9563720768824bcb66e71463f6900]')
        self.assertEqual(repr(PointVector()),'[]')
        self.assertEqual(str(PointVector()),'[]')

    def test_neg(self):
        # Test negation
        self.assertEqual(-PointVector(),PointVector())
        self.assertEqual(-PointVector([Z,G,G+G,G+G+G]),PointVector([Z,-G,-G-G,-G-G-G]))


# ScalarVector class
class TestScalarVector(unittest.TestCase):
    def test_init(self):
        # Test valid construction
        self.assertEqual(ScalarVector(),ScalarVector([]))
        self.assertEqual(ScalarVector(),ScalarVector(None))
        ScalarVector([Scalar(0)])
        ScalarVector([Scalar(0),Scalar(1)])

        # Test invalid construction
        with self.assertRaises(TypeError):
            ScalarVector(1)
        with self.assertRaises(TypeError):
            ScalarVector([Scalar(0),None])

    def test_eq(self):
        # Test valid equality
        self.assertEqual(ScalarVector([Scalar(0)]),ScalarVector([Scalar(0)]))
        self.assertEqual(ScalarVector([Scalar(0),Scalar(1)]),ScalarVector([Scalar(0),Scalar(1)]))

        # Test invalid equality
        with self.assertRaises(TypeError):
            ScalarVector() == None
        with self.assertRaises(TypeError):
            None == ScalarVector()

    def test_ne(self):
        # Test valid inequality
        self.assertNotEqual(ScalarVector(),ScalarVector([Scalar(0)]))
        self.assertNotEqual(ScalarVector([Scalar(0)]),ScalarVector([Scalar(1)]))
        self.assertNotEqual(ScalarVector([Scalar(0)]),ScalarVector([Scalar(0),Scalar(0)]))

        # Test invalid inequality
        with self.assertRaises(TypeError):
            ScalarVector() != None
        with self.assertRaises(TypeError):
            None != ScalarVector()

    def test_add(self):
        # Test valid addition
        self.assertEqual(ScalarVector([Scalar(0),Scalar(1),Scalar(2)]) + ScalarVector([Scalar(1),Scalar(2),Scalar(3)]),ScalarVector([Scalar(1),Scalar(3),Scalar(5)]))

        # Test invalid addition
        with self.assertRaises(TypeError):
            ScalarVector([Scalar(0)]) + ScalarVector()
        with self.assertRaises(TypeError):
            ScalarVector([Scalar(0)]) + ScalarVector([Scalar(0),Scalar(1)])
        with self.assertRaises(TypeError):
            ScalarVector([Scalar(0)]) + None
        with self.assertRaises(TypeError):
            None + ScalarVector([Scalar(0)])

    def test_sub(self):
        # Test valid subtraction
        self.assertEqual(ScalarVector([Scalar(0),Scalar(1),Scalar(2)]) - ScalarVector([Scalar(1),Scalar(2),Scalar(3)]),ScalarVector([Scalar(-1),Scalar(-1),Scalar(-1)]))

        # Test invalid subtraction
        with self.assertRaises(TypeError):
            ScalarVector([Scalar(0)]) - ScalarVector()
        with self.assertRaises(TypeError):
            ScalarVector([Scalar(0)]) - ScalarVector([Scalar(0),Scalar(1)])
        with self.assertRaises(TypeError):
            ScalarVector([Scalar(0)]) - None
        with self.assertRaises(TypeError):
            None - ScalarVector([Scalar(0)])

    def test_mul(self):
        # Test ScalarVector-Scalar multiplication
        self.assertEqual(ScalarVector([Scalar(1),Scalar(2),Scalar(3)])*Scalar(2),ScalarVector([Scalar(2),Scalar(4),Scalar(6)]))
        self.assertEqual(ScalarVector([Scalar(1),Scalar(2),Scalar(3)])*Scalar(0),ScalarVector([Scalar(0),Scalar(0),Scalar(0)]))

        # Test Scalar-ScalarVector multiplication
        self.assertEqual(Scalar(2)*ScalarVector([Scalar(1),Scalar(2),Scalar(3)]),ScalarVector([Scalar(2),Scalar(4),Scalar(6)]))
        self.assertEqual(Scalar(0)*ScalarVector([Scalar(1),Scalar(2),Scalar(3)]),ScalarVector([Scalar(0),Scalar(0),Scalar(0)]))

        # Test ScalarVector-ScalarVector multiplication
        self.assertEqual(ScalarVector([Scalar(1),Scalar(2),Scalar(3)])*ScalarVector([Scalar(2),Scalar(3),Scalar(4)]),ScalarVector([Scalar(2),Scalar(6),Scalar(12)]))

        # Test invalid multiplication
        with self.assertRaises(TypeError):
            ScalarVector([Scalar(1),Scalar(2),Scalar(3)])*None
        with self.assertRaises(TypeError):
            None*ScalarVector([Scalar(1),Scalar(2),Scalar(3)])
        with self.assertRaises(TypeError):
            ScalarVector([Scalar(1),Scalar(2),Scalar(3)])*ScalarVector([Scalar(2),Scalar(3)])

    def test_sum(self):
        # Test sum
        self.assertEqual(ScalarVector([Scalar(0),Scalar(1),Scalar(2)]).sum(),Scalar(3))
        self.assertEqual(ScalarVector().sum(),Scalar(0))

    def test_pow(self):
        # Test valid inner product
        self.assertEqual(ScalarVector([Scalar(0),Scalar(1),Scalar(2)])**ScalarVector([Scalar(1),Scalar(2),Scalar(3)]),Scalar(8))
        self.assertEqual(ScalarVector([Scalar(1),Scalar(2),Scalar(3)])**ScalarVector([Scalar(0),Scalar(1),Scalar(2)]),Scalar(8))

        # Test valid multiscalar multiplication
        self.assertEqual(ScalarVector([Scalar(1),Scalar(2)])**PointVector([G,G+G]),Scalar(5)*G)
        self.assertEqual(ScalarVector()**PointVector(),Z)

        # Test invalid operations
        with self.assertRaises(TypeError):
            ScalarVector([Scalar(0),Scalar(1)])**ScalarVector([Scalar(0)])
        with self.assertRaises(TypeError):
            ScalarVector([Scalar(0),Scalar(1)])**PointVector([G])
        with self.assertRaises(TypeError):
            ScalarVector()**None
        with self.assertRaises(TypeError):
            None**ScalarVector()

    def test_len(self):
        # Test length
        self.assertEqual(len(ScalarVector()),0)
        self.assertEqual(len(ScalarVector([Scalar(0)])),1)
        self.assertEqual(len(ScalarVector([Scalar(0),Scalar(1)])),2)

    def test_getitem(self):
        # Test valid gets
        s = ScalarVector([Scalar(0),Scalar(1),Scalar(2)])
        self.assertEqual(s[0],Scalar(0))
        self.assertEqual(s[1],Scalar(1))
        self.assertEqual(s[2],Scalar(2))
        self.assertEqual(s[0:-1],ScalarVector([Scalar(0),Scalar(1)]))

        # Test invalid get
        with self.assertRaises(IndexError):
            s[3]

    def test_setitem(self):
        # Test valid sets
        s = ScalarVector([Scalar(0),Scalar(1),Scalar(2)])
        s[0] = Scalar(-1)
        self.assertEqual(s,ScalarVector([Scalar(-1),Scalar(1),Scalar(2)]))

        # Test invalid sets
        with self.assertRaises(IndexError):
            s[3] = Scalar(0)
        with self.assertRaises(TypeError):
            s[0] = None

    def test_append(self):
        # Test valid append
        s = ScalarVector()
        s.append(Scalar(0))
        self.assertEqual(s,ScalarVector([Scalar(0)]))
        s.append(Scalar(1))
        self.assertEqual(s,ScalarVector([Scalar(0),Scalar(1)]))
        
        # Test invalid append
        with self.assertRaises(TypeError):
            s.append(None)

    def test_extend(self):
        # Test valid extend
        s = ScalarVector()
        s.extend(ScalarVector())
        self.assertEqual(s,ScalarVector())
        s.extend(ScalarVector([Scalar(0),Scalar(1)]))
        self.assertEqual(s,ScalarVector([Scalar(0),Scalar(1)]))
        s.extend(ScalarVector([Scalar(2)]))
        self.assertEqual(s,ScalarVector([Scalar(0),Scalar(1),Scalar(2)]))
        
        # Test invalid extend
        with self.assertRaises(TypeError):
            s.extend(None)
        with self.assertRaises(TypeError):
            s.extend(Scalar(0))
        with self.assertRaises(TypeError):
            s.extend([Scalar(0)])

    def test_repr(self):
        # Test known representation
        self.assertEqual(repr(ScalarVector([Scalar(0),Scalar(1)])),'[000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000, 010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000]')
        self.assertEqual(str(ScalarVector([Scalar(0),Scalar(1)])),'[000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000, 010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000]')
        self.assertEqual(repr(ScalarVector()),'[]')
        self.assertEqual(str(ScalarVector()),'[]')

    def test_invert(self):
        # Test nonzero inversion
        self.assertEqual(ScalarVector([Scalar(1),Scalar(2),Scalar(3)]).invert(),ScalarVector([Scalar(1),Scalar(2).invert(),Scalar(3).invert()]))
        self.assertEqual(ScalarVector([Scalar(1),Scalar(2),Scalar(3)]).invert(allow_zero=True),ScalarVector([Scalar(1),Scalar(2).invert(),Scalar(3).invert()]))

        # Test zero inversion
        self.assertEqual(ScalarVector([Scalar(0),Scalar(1),Scalar(2)]).invert(allow_zero=True),ScalarVector([Scalar(0),Scalar(1).invert(),Scalar(2).invert()]))
        with self.assertRaises(ZeroDivisionError):
            ScalarVector([Scalar(0),Scalar(1),Scalar(2)]).invert()

    def test_neg(self):
        # Test negation
        self.assertEqual(-ScalarVector(),ScalarVector())
        self.assertEqual(-ScalarVector([Scalar(0),Scalar(1),Scalar(2)]),ScalarVector([Scalar(0),-Scalar(1),Scalar(-2)]))


# Hash operations
class TestHash(unittest.TestCase):
    def test_hash_to_point(self):
        # Test good hash types
        hash_to_point('')
        hash_to_point([])
        hash_to_point(G)
        hash_to_point('test message')
        hash_to_point(Scalar(0))
        hash_to_point(PointVector())
        hash_to_point(ScalarVector())
        
        # Test equal hash types
        self.assertEqual(hash_to_point(ScalarVector()),hash_to_point([]))
        self.assertEqual(hash_to_point(PointVector()),hash_to_point([]))

        # Test unequal hash types
        self.assertNotEqual(hash_to_point(ScalarVector()),hash_to_point(ScalarVector([Scalar(0)])))
        self.assertNotEqual(hash_to_point(Scalar(0)),hash_to_point(0))
        self.assertNotEqual(hash_to_point([0,None]),hash_to_point([0]))

        # Test bad hash
        with self.assertRaises(TypeError):
            hash_to_point(0,None)

    def test_hash_to_scalar(self):
        # Test good hash types
        hash_to_scalar('')
        hash_to_scalar([])
        hash_to_scalar(G)
        hash_to_scalar('test message')
        hash_to_scalar(Scalar(0))
        hash_to_scalar(PointVector())
        hash_to_scalar(ScalarVector())
        
        # Test equal hash types
        self.assertEqual(hash_to_scalar(ScalarVector()),hash_to_scalar([]))
        self.assertEqual(hash_to_scalar(PointVector()),hash_to_scalar([]))

        # Test unequal hash types
        self.assertNotEqual(hash_to_scalar(ScalarVector()),hash_to_scalar(ScalarVector([Scalar(0)])))
        self.assertNotEqual(hash_to_scalar(Scalar(0)),hash_to_scalar(0))
        self.assertNotEqual(hash_to_scalar([0,None]),hash_to_scalar([0]))

        # Test bad hash
        with self.assertRaises(TypeError):
            hash_to_scalar(0,None)


# Random functions
class TestRandom(unittest.TestCase):
    def test_random_scalar(self):
        # Test random values
        self.assertIsInstance(random_scalar(),Scalar)
        self.assertIsInstance(random_scalar(zero=True),Scalar)
        self.assertIsNotNone(random_scalar())
        self.assertIsNotNone(random_scalar(zero=True))
        self.assertNotEqual(random_scalar(),random_scalar())
        self.assertNotEqual(random_scalar(zero=True),random_scalar(zero=True))

    def test_random_scalar(self):
        # Test random values
        self.assertIsInstance(random_point(),Point)
        self.assertIsNotNone(random_point())
        self.assertNotEqual(random_point(),random_point())


# Multiscalar multiplication
class TestMultiexp(unittest.TestCase):
    def test_multiexp(self):
        s3 = ScalarVector([Scalar(0),Scalar(1),Scalar(2)])
        s2 = s3[0:2]
        s1 = s3[0:1]
        s0 = s3[0:0]
        P3 = PointVector([Z,G,G+G])
        P2 = P3[0:2]
        P1 = P3[0:1]
        P0 = P3[0:0]

        # Test valid operations
        self.assertEqual(multiexp(zip(P3,s3)),Scalar(5)*G)
        self.assertEqual(multiexp(s3,P3),Scalar(5)*G)
        self.assertEqual(multiexp(s2,P2),G)
        self.assertEqual(multiexp(s1,P1),Z)
        self.assertEqual(multiexp(s0,P0),Z)

        # Test invalid operations
        with self.assertRaises(ValueError):
            multiexp(s3,P3,None)
        with self.assertRaises(TypeError):
            multiexp(P3,s3)
        with self.assertRaises(TypeError):
            multiexp(zip(s3,P3))
        with self.assertRaises(TypeError):
            multiexp(P3,s2)

for test in [TestScalar,TestPoint,TestPointVector,TestScalarVector,TestHash,TestRandom,TestMultiexp]:
    unittest.TextTestRunner(verbosity=2,failfast=True).run(unittest.TestLoader().loadTestsFromTestCase(test))
