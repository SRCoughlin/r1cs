use std::collections::HashMap;

use num::BigUint;
use num_traits::One;

use crate::bits::BinaryExpression;
use crate::expression::Expression;
use crate::gadget_builder::GadgetBuilder;
use crate::wire_values::WireValues;

impl GadgetBuilder {
    /// Split `x` into `bits` bit wires. Assumes `x < 2^bits`.
    pub fn split(&mut self, x: Expression, bits: usize) -> BinaryExpression {
        let binary_wire = self.binary_wire(bits);

        {
            let x = x.clone();
            let binary_wire = binary_wire.clone();

            self.generator(
                x.dependencies(),
                move |values: &mut WireValues| {
                    let value = x.evaluate(values);
                    assert!(value.bits() <= bits);
                    for i in 0..bits {
                        values.set_boolean(binary_wire.bits[i], value.bit(i));
                    }
                },
            );
        }

        // TODO: Use BinaryExpression.join? A bit redundant as is.
        let mut bit_weights = HashMap::new();
        for (i, &wire) in binary_wire.bits.iter().enumerate() {
            bit_weights.insert(wire.wire(), (BigUint::one() << i).into());
        }
        let weighted_sum = Expression::new(bit_weights);
        self.assert_equal(x.into(), weighted_sum);

        // TODO: Needs a comparison to verify that no overflow occurred, i.e., that the sum is less
        // than the prime field size.

        binary_wire.into()
    }
}

#[cfg(test)]
mod tests {
    use crate::gadget_builder::GadgetBuilder;

    #[test]
    fn split_19_32() {
        let mut builder = GadgetBuilder::new();
        let wire = builder.wire();
        let bit_wires = builder.split(wire.into(), 32);
        let gadget = builder.build();

        let mut wire_values = values!(wire.clone() => 19.into());
        assert!(gadget.execute(&mut wire_values));

        assert_eq!(true, bit_wires.bits[0].evaluate(&wire_values));
        assert_eq!(true, bit_wires.bits[1].evaluate(&wire_values));
        assert_eq!(false, bit_wires.bits[2].evaluate(&wire_values));
        assert_eq!(false, bit_wires.bits[3].evaluate(&wire_values));
        assert_eq!(true, bit_wires.bits[4].evaluate(&wire_values));
        assert_eq!(false, bit_wires.bits[5].evaluate(&wire_values));
        assert_eq!(false, bit_wires.bits[6].evaluate(&wire_values));
    }
}