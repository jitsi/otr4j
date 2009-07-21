package net.java.otr4j.message;

@SuppressWarnings("serial")
public abstract class OtrWrappedType<T> extends OtrObject {
	private T prim;

	public OtrWrappedType(T prim) {
		this.setPrim(prim);
	}

	protected void setPrim(T prim) {
		this.prim = prim;
	}

	protected T getPrim() {
		return prim;
	}
}
