# Test suite for dumb448

from dumb448 import *
import unittest

class TestPoint(unittest.TestCase):
    def test_point_ops(self):
        with self.assertRaises(TypeError):
            Point('test',None)

        self.assertEqual(Z+Z,Z)
        self.assertEqual(G+Z,G)
        self.assertEqual(Z+G,G)
        self.assertEqual(G-G,Z)

        self.assertFalse(Point(0,0).on_curve())
        self.assertTrue(G.on_curve())
        self.assertTrue(Z.on_curve())

class TestScalar(unittest.TestCase):
    def test_scalar_ops(self):
        with self.assertRaises(TypeError):
            Scalar(None)
        with self.assertRaises(TypeError):
            Scalar('test')

        self.assertEqual(Scalar(0),Scalar(l))
        self.assertEqual(Scalar(0)+Scalar(1),Scalar(1))
        self.assertEqual(Scalar(0)-Scalar(1),Scalar(-1))
        self.assertEqual(Scalar(1)*Scalar(1),Scalar(1))
        self.assertEqual(Scalar(2)/Scalar(2),Scalar(1))
        self.assertEqual(Scalar(3)/Scalar(2),Scalar(1))
        self.assertEqual(Scalar(0)/Scalar(2),Scalar(0))
        self.assertEqual(Scalar(2)**0,Scalar(1))
        self.assertEqual(Scalar(2)**1,Scalar(2))
        self.assertEqual(Scalar(2)**2,Scalar(4))
        self.assertEqual(Scalar(2)**3,Scalar(8))
        self.assertEqual(Scalar(1)**0,Scalar(1))
        self.assertEqual(Scalar(1)**1,Scalar(1))
        self.assertEqual(Scalar(1)**2,Scalar(1))
        self.assertEqual(Scalar(0)**1,Scalar(0))
        self.assertEqual(Scalar(0)**2,Scalar(0))

        self.assertEqual(Scalar(1).invert(),Scalar(1))
        with self.assertRaises(ZeroDivisionError):
            Scalar(0).invert()
        self.assertEqual(Scalar(2)*Scalar(2).invert(),Scalar(1))

    def test_equality(self):
        self.assertTrue(Scalar(0) == Scalar(0))
        with self.assertRaises(TypeError):
            Scalar(0) == 0

        self.assertTrue(Scalar(1) != Scalar(0))
        with self.assertRaises(TypeError):
            Scalar(1) != 0

        self.assertTrue(Scalar(1) > Scalar(0))
        with self.assertRaises(TypeError):
            Scalar(1) > 0
        self.assertTrue(Scalar(1) >= Scalar(0))
        with self.assertRaises(TypeError):
            Scalar(1) >= 0

        self.assertFalse(Scalar(1) < Scalar(0))
        with self.assertRaises(TypeError):
            Scalar(1) < 0
        self.assertFalse(Scalar(1) <= Scalar(0))
        with self.assertRaises(TypeError):
            Scalar(1) <= 0

        self.assertFalse(Scalar(0) > Scalar(0))
        self.assertTrue(Scalar(0) >= Scalar(0))

        self.assertFalse(Scalar(0) < Scalar(0))
        self.assertTrue(Scalar(0) <= Scalar(0))

        self.assertTrue(Scalar(3) % Scalar(2),Scalar(1))
        self.assertTrue(Scalar(3) % 2,Scalar(1))
        self.assertTrue(Scalar(2) % Scalar(2),Scalar(0))
        self.assertTrue(Scalar(2) % 2,Scalar(0))

class TestMixed(unittest.TestCase):
    def test_mixed_ops(self):
        self.assertEqual(G*Scalar(0),Z)
        self.assertEqual(G*Scalar(1),G)
        self.assertEqual(G*Scalar(2),G+G)
        self.assertEqual(G+G*Scalar(-1),Z)
        self.assertEqual(G-G*Scalar(-1),G+G)

        self.assertEqual(Scalar(0)*G,Z)
        self.assertEqual(Scalar(1)*G,G)

        with self.assertRaises(TypeError):
            G+Scalar(1)
        with self.assertRaises(TypeError):
            G-Scalar(1)
        with self.assertRaises(TypeError):
            G*Z
        with self.assertRaises(TypeError):
            Scalar(1)+G
        with self.assertRaises(TypeError):
            Scalar(1)-G
        with self.assertRaises(TypeError):
            Scalar(1)/G
        with self.assertRaises(TypeError):
            G == Scalar(1)
        with self.assertRaises(TypeError):
            Scalar(1) == G

class TestOthers(unittest.TestCase):
    def test_hashing(self):
        hash_to_point('The Human Fund: Money For People')
        hash_to_scalar('The Human Fund: Money For People')
        hash_to_point(G)
        hash_to_scalar(G)
        hash_to_point(8675309)
        hash_to_scalar(8675309)
        hash_to_point('The Human Fund: Money For People',G,8675309)
        hash_to_scalar('The Human Fund: Money For People',G,8675309)
        hash_to_point([Scalar(0),Scalar(1),G])
        hash_to_scalar([Scalar(0),Scalar(1),G])

        with self.assertRaises(TypeError):
            hash_to_scalar(None)
        with self.assertRaises(TypeError):
            hash_to_point(None)
        with self.assertRaises(TypeError):
            hash_to_scalar(G,None)
        with self.assertRaises(TypeError):
            hash_to_point(G,None)

    def test_random(self):
        random_scalar()
        random_scalar(zero=True)
        random_scalar(zero=False)
        random_point()

class TestMultiexp(unittest.TestCase):
    def test_0(self):
        scalars = ScalarVector([])
        points = PointVector([])
        self.assertEqual(multiexp(scalars,points),Z)

    def test_bad_size(self):
        scalars = ScalarVector([Scalar(0)])
        points = PointVector([G,Z])
        with self.assertRaises(IndexError):
            multiexp(scalars,points)

    def test_1_G_0(self):
        scalars = ScalarVector([Scalar(0)])
        points = PointVector([G])
        self.assertEqual(multiexp(scalars,points),Z)

    def test_1_G_1(self):
        scalars = ScalarVector([Scalar(1)])
        points = PointVector([G])
        self.assertEqual(multiexp(scalars,points),G)

    def test_1_G_2(self):
        scalars = ScalarVector([Scalar(2)])
        points = PointVector([G])
        self.assertEqual(multiexp(scalars,points),G*Scalar(2))

    def test_2_G_1_H_2(self):
        H = hash_to_point(G)
        scalars = ScalarVector([Scalar(1),Scalar(2)])
        points = PointVector([G,H])
        self.assertEqual(multiexp(scalars,points),G+H*Scalar(2))

    def test_2_G_2_G_n1(self):
        scalars = ScalarVector([Scalar(2),Scalar(-1)])
        points = PointVector([G,G])
        self.assertEqual(multiexp(scalars,points),G)

    def test_8_random(self):
        l = 8
        scalars = ScalarVector([random_scalar() for i in range(l)])
        points = PointVector([random_point() for i in range(l)])

        result = Z
        for i in range(l):
            result += points[i]*scalars[i]
        self.assertEqual(multiexp(scalars,points),result)

class TestVectorOps(unittest.TestCase):
    def test_point_vector_add(self):
        l = 3
        V = PointVector([random_point() for i in range(l)])
        W = PointVector([random_point() for i in range(l)])
        X = V+W

        self.assertEqual(len(X),l)
        for i in range(l):
            self.assertEqual(X[i],V[i]+W[i])

    def test_point_vector_sub(self):
        l = 3
        V = PointVector([random_point() for i in range(l)])
        W = PointVector([random_point() for i in range(l)])
        X = V-W

        self.assertEqual(len(X),l)
        for i in range(l):
            self.assertEqual(X[i],V[i]-W[i])

    def test_point_vector_mul_scalar(self):
        l = 3
        V = PointVector([random_point() for i in range(l)])
        s = random_scalar()
        W = V*s

        self.assertEqual(len(W),l)
        for i in range(l):
            self.assertEqual(W[i],V[i]*s)

    def test_point_vector_mul_scalar_vector(self):
        l = 3
        V = PointVector([random_point() for i in range(l)])
        v = ScalarVector([random_scalar() for i in range(l)])
        W = V*v

        R = Z
        for i in range(l):
            R += V[i]*v[i]
        self.assertEqual(W,R)

    def test_point_vector_hadamard(self):
        l = 3
        V = PointVector([random_point() for i in range(l)])
        W = PointVector([random_point() for i in range(l)])
        X = V*W

        self.assertEqual(len(X),l)
        for i in range(l):
            self.assertEqual(X[i],V[i]+W[i])

    def test_point_vector_extend(self):
        l = 3
        points = [random_point() for i in range(2*l)]
        V = PointVector(points[:l])
        W = PointVector(points[l:])
        V.extend(W)

        T = PointVector(points)
        self.assertEqual(len(V),len(T))
        self.assertEqual(V.points,T.points)

    def test_point_vector_slice(self):
        l = 3
        points = [random_point() for i in range(2*l)]
        V = PointVector(points)
        W = V[:l]

        self.assertEqual(len(W),l)
        self.assertEqual(W.points,points[:l])

    def test_scalar_vector_add(self):
        l = 3
        v = ScalarVector([random_scalar() for i in range(l)])
        w = ScalarVector([random_scalar() for i in range(l)])
        x = v+w

        self.assertEqual(len(x),l)
        for i in range(l):
            self.assertEqual(x[i],v[i]+w[i])

    def test_scalar_vector_sub(self):
        l = 3
        v = ScalarVector([random_scalar() for i in range(l)])
        w = ScalarVector([random_scalar() for i in range(l)])
        x = v-w

        self.assertEqual(len(x),l)
        for i in range(l):
            self.assertEqual(x[i],v[i]-w[i])

    def test_scalar_vector_mul_scalar(self):
        l = 3
        v = ScalarVector([random_scalar() for i in range(l)])
        s = random_scalar()
        w = v*s

        self.assertEqual(len(w),l)
        for i in range(l):
            self.assertEqual(w[i],v[i]*s)

    def test_scalar_vector_hadamard(self):
        l = 3
        v = ScalarVector([random_scalar() for i in range(l)])
        w = ScalarVector([random_scalar() for i in range(l)])
        x = v*w

        self.assertEqual(len(x),l)
        for i in range(l):
            self.assertEqual(x[i],v[i]*w[i])

    def test_inner_product(self):
        l = 3
        v = ScalarVector([random_scalar() for i in range(l)])
        w = ScalarVector([random_scalar() for i in range(l)])
        x = v**w

        r = Scalar(0)
        for i in range(l):
            r += v[i]*w[i]
        self.assertEqual(r,x)

    def test_scalar_vector_sum(self):
        l = 3
        v = ScalarVector([random_scalar() for i in range(l)])
        
        r = Scalar(0)
        for i in range(l):
            r += v[i]
        self.assertEqual(r,v.sum())

    def test_scalar_vector_extend(self):
        v = ScalarVector([Scalar(0),Scalar(1)])
        w = ScalarVector([Scalar(2),Scalar(3)])
        v.extend(w)

        t = ScalarVector([Scalar(0),Scalar(1),Scalar(2),Scalar(3)])
        self.assertEqual(len(v),len(t))
        self.assertEqual(v.scalars,t.scalars)

    def test_scalar_vector_slice(self):
        l = 3
        scalars = [random_scalar() for i in range(2*l)]
        v = ScalarVector(scalars)
        w = v[:l]

        self.assertEqual(len(w),l)
        self.assertEqual(w.scalars,scalars[:l])

    def test_batch_inversion(self):
        l = 8
        v = ScalarVector([random_scalar() for i in range(l)])
        v.append(Scalar(1))
        v.append(Scalar(l-1))
        w = v.invert()

        for i in range(len(v)):
            self.assertEqual(v[i]*w[i],Scalar(1))

    def test_bad_batch_inversion(self):
        with self.assertRaises(ArithmeticError):
            ScalarVector([Scalar(1),Scalar(0)]).invert()

for test in [TestPoint,TestScalar,TestMixed,TestOthers,TestVectorOps,TestMultiexp]:
    unittest.TextTestRunner(verbosity=2,failfast=True).run(unittest.TestLoader().loadTestsFromTestCase(test))
