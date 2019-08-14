use core::borrow::Borrow;

use crate::constraint::Constraint;
use crate::expression::{BooleanExpression, Expression};
use crate::field::{Element, Field};
use crate::gadget::Gadget;
use crate::wire::{BinaryWire, BooleanWire, Wire};
use crate::wire_values::WireValues;
use crate::witness_generator::WitnessGenerator;

pub struct GadgetBuilder<F: Field> {
    next_wire_index: u32,
    constraints: Vec<Constraint<F>>,
    witness_generators: Vec<WitnessGenerator<F>>,
}

/// A utility for building `Gadget`s. See the readme for examples.
// Default for a builder seems weird.
#[allow(clippy::new_without_default)]
impl<F: Field> GadgetBuilder<F> {
    pub fn new() -> Self {
        GadgetBuilder {
            next_wire_index: 1,
            constraints: Vec::new(),
            witness_generators: Vec::new(),
        }
    }

    /// Add a wire to the gadget. It will start with no generator and no associated constraints.
    pub fn wire(&mut self) -> Wire {
        let index = self.next_wire_index;
        self.next_wire_index += 1;
        Wire { index }
    }

    /// Add a wire to the gadget, whose value is constrained to equal 0 or 1.
    pub fn boolean_wire(&mut self) -> BooleanWire {
        let w = self.wire();
        self.assert_boolean(Expression::from(w));
        BooleanWire::new_unsafe(w)
    }

    /// Add `n` wires to the gadget. They will start with no generator and no associated
    /// constraints.
    pub fn wires(&mut self, n: usize) -> Vec<Wire> {
        (0..n).map(|_i| self.wire()).collect()
    }

    /// Add a binary wire comprised of `n` bits to the gadget.
    pub fn binary_wire(&mut self, n: usize) -> BinaryWire {
        BinaryWire { bits: (0..n).map(|_i| self.boolean_wire()).collect() }
    }

    /// Add a generator function for setting certain wire values.
    pub fn generator<T>(&mut self, dependencies: Vec<Wire>, generate: T)
        where T: Fn(&mut WireValues<F>) + 'static {
        self.witness_generators.push(WitnessGenerator::new(dependencies, generate));
    }

    /// x == y
    pub fn equal<E1, E2>(&mut self, x: E1, y: E2) -> BooleanExpression<F>
        where E1: Borrow<Expression<F>>, E2: Borrow<Expression<F>> {
        self.zero(x.borrow() - y.borrow())
    }

    /// x == 0
    pub fn zero<E: Borrow<Expression<F>>>(&mut self, x: E) -> BooleanExpression<F> {
        let nonzero = self.nonzero(x);
        self.not(nonzero)
    }

    /// x != 0
    pub fn nonzero<E: Borrow<Expression<F>>>(&mut self, x: E) -> BooleanExpression<F> {
        let x = x.borrow();

        // See the Pinocchio paper for an explanation.
        let (y, m) = (self.wire(), self.wire());
        let (y_exp, m_exp) = (Expression::from(y), Expression::from(m));
        self.assert_product(x, m_exp, &y_exp);
        self.assert_product(Expression::one() - &y_exp, x, Expression::zero());

        let x = x.clone();
        self.generator(
            x.dependencies(),
            move |values: &mut WireValues<F>| {
                let x_value = x.evaluate(values);
                let y_value = if x_value.is_nonzero() {
                    Element::one()
                } else {
                    Element::zero()
                };
                let m_value: Element<F> = if x_value.is_nonzero() {
                    &y_value / x_value
                } else {
                    // The value of m doesn't matter if x = 0.
                    Element::from(42u8)
                };
                values.set(m, m_value);
                values.set(y, y_value);
            },
        );

        // y can only be 0 or 1 based on the constraints above.
        BooleanExpression::new_unsafe(y_exp)
    }

    /// if c { x } else { y }. Assumes c is binary.
    pub fn selection<BE, E1, E2>(&mut self, c: BE, x: E1, y: E2) -> Expression<F>
        where BE: Borrow<BooleanExpression<F>>, E1: Borrow<Expression<F>>, E2: Borrow<Expression<F>> {
        let c = c.borrow();
        let x = x.borrow();
        let y = y.borrow();
        y + self.product(c.expression(), x - y)
    }

    /// Assert that x * y = z;
    pub fn assert_product<E1, E2, E3>(&mut self, x: E1, y: E2, z: E3)
        where E1: Borrow<Expression<F>>, E2: Borrow<Expression<F>>, E3: Borrow<Expression<F>> {
        self.constraints.push(Constraint {
            a: x.borrow().clone(),
            b: y.borrow().clone(),
            c: z.borrow().clone(),
        });
    }

    /// Assert that the given quantity is in [0, 1].
    pub fn assert_boolean<E: Borrow<Expression<F>>>(&mut self, x: E) -> BooleanExpression<F> {
        self.assert_product(x.borrow(), x.borrow() - Expression::one(), Expression::zero());
        BooleanExpression::new_unsafe(x.borrow().clone())
    }

    /// Assert that x == y.
    pub fn assert_equal<E1, E2>(&mut self, x: E1, y: E2)
        where E1: Borrow<Expression<F>>, E2: Borrow<Expression<F>> {
        self.assert_product(x, Expression::one(), y);
    }

    /// Assert that x != y.
    pub fn assert_nonequal<E1, E2>(&mut self, x: E1, y: E2)
        where E1: Borrow<Expression<F>>, E2: Borrow<Expression<F>> {
        let difference = x.borrow() - y.borrow();
        self.assert_nonzero(difference);
    }

    /// Assert that x == 0.
    pub fn assert_zero<E: Borrow<Expression<F>>>(&mut self, x: E) {
        self.assert_equal(x, Expression::zero());
    }

    /// Assert that x != 0.
    pub fn assert_nonzero<E: Borrow<Expression<F>>>(&mut self, x: E) {
        // A field element is non-zero iff it has a multiplicative inverse.
        // We don't care what the inverse is, but calling inverse(x) will require that it exists.
        self.inverse(x);
    }

    /// Assert that x == 1.
    pub fn assert_true<BE: Borrow<BooleanExpression<F>>>(&mut self, x: BE) {
        self.assert_equal(x.borrow().expression(), Expression::one());
    }

    /// Assert that x == 0.
    pub fn assert_false<BE: Borrow<BooleanExpression<F>>>(&mut self, x: BE) {
        self.assert_equal(x.borrow().expression(), Expression::zero());
    }

    pub fn build(self) -> Gadget<F> {
        Gadget {
            constraints: self.constraints,
            witness_generators: self.witness_generators,
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::expression::{BooleanExpression, Expression};
    use crate::field::{Bn128, Element};
    use crate::gadget_builder::GadgetBuilder;
    use crate::test_util::{assert_eq_false, assert_eq_true};

    #[test]
    fn assert_binary_0_1() {
        let mut builder = GadgetBuilder::<Bn128>::new();
        let x = builder.wire();
        builder.assert_boolean(Expression::from(x));
        let gadget = builder.build();

        // With x = 0, the constraint should be satisfied.
        let mut values0 = values!(x => 0u8.into());
        assert!(gadget.execute(&mut values0));

        // With x = 1, the constraint should be satisfied.
        let mut values1 = values!(x => 1u8.into());
        assert!(gadget.execute(&mut values1));
    }

    #[test]
    fn assert_binary_2() {
        let mut builder = GadgetBuilder::<Bn128>::new();
        let x = builder.wire();
        builder.assert_boolean(Expression::from(x));
        let gadget = builder.build();

        // With x = 2, the constraint should NOT be satisfied.
        let mut values2 = values!(x => 2u8.into());
        assert!(!gadget.execute(&mut values2));
    }

    #[test]
    fn selection() {
        let mut builder = GadgetBuilder::<Bn128>::new();
        let (c, x, y) = (builder.boolean_wire(), builder.wire(), builder.wire());
        let selection = builder.selection(
            BooleanExpression::from(c), Expression::from(x), Expression::from(y));
        let gadget = builder.build();

        let values_3_5 = values!(x => 3u8.into(), y => 5u8.into());

        let mut values_0_3_5 = values_3_5.clone();
        values_0_3_5.set_boolean(c, false);
        assert!(gadget.execute(&mut values_0_3_5));
        assert_eq!(Element::from(5u8), selection.evaluate(&values_0_3_5));

        let mut values_1_3_5 = values_3_5.clone();
        values_1_3_5.set_boolean(c, true);
        assert!(gadget.execute(&mut values_1_3_5));
        assert_eq!(Element::from(3u8), selection.evaluate(&values_1_3_5));
    }

    #[test]
    fn equal() {
        let mut builder = GadgetBuilder::<Bn128>::new();
        let (x, y) = (builder.wire(), builder.wire());
        let equal = builder.equal(Expression::from(x), Expression::from(y));
        let gadget = builder.build();

        let mut values_7_7 = values!(x => 7u8.into(), y => 7u8.into());
        assert!(gadget.execute(&mut values_7_7));
        assert_eq_true(&equal, &values_7_7);

        let mut values_6_7 = values!(x => 6u8.into(), y => 7u8.into());
        assert!(gadget.execute(&mut values_6_7));
        assert_eq_false(&equal, &values_6_7);

        let mut values_7_13 = values!(x => 7u8.into(), y => 13u8.into());
        assert!(gadget.execute(&mut values_7_13));
        assert_eq_false(&equal, &values_7_13);
    }
}
