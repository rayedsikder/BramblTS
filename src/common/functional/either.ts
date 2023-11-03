/* eslint-disable @typescript-eslint/no-unused-vars */
/* eslint-disable @typescript-eslint/no-explicit-any */
export interface Option<T> {
  isDefined: boolean;
  getOrElse(defaultValue: T): T;
  getOrThrow(exception?: Error): T;
  forEach(f: (t: T) => void): void;
  map<U>(f: (t: T) => U): Option<U>;
  flatMap<U>(f: (t: T) => Option<U>): Option<U>;
  fold<U>(onDefined: (t: T) => U, onUndefined: () => U): U;
}

export class Either<L, R> {
  private readonly _left: L | null;
  private readonly _right: R | null;

  private constructor(left: L | null, right: R | null) {
    this._left = left;
    this._right = right;
  }

  static left<L>(left: L): Either<L, null> {
    return new Either(left, null);
  }

  static right<R>(right: R): Either<null, R> {
    return new Either(null, right);
  }

  static unit(): Either<null, Unit> {
    return new Either(null, {});
  }

  get isLeft(): boolean {
    return this._left !== null;
  }

  get isRight(): boolean {
    return this._right !== null;
  }

  get left(): L {
    if (!this.isLeft) {
      throw new Error('Cannot get left value of right Either');
    }
    return this._left!;
  }

  get right(): R {
    if (!this.isRight) {
      throw new Error('Cannot get right value of left Either');
    }
    return this._right!;
  }

  map<T>(f: (value: R) => T): Either<L, null> | Either<null, T> {
    return this.isRight ? Either.right(f(this.right)) : Either.left(this.left);
  }

  flatMap<T>(f: (value: R) => Either<L, T>): Either<L, T> | Either<L, null> {
    return this.isRight ? f(this.right) : Either.left(this.left);
  }

  mapLeft<T>(f: (value: L) => T): Either<T, null> | Either<null, R> {
    return this.isLeft ? Either.left(f(this.left)) : Either.right(this.right);
  }

  flatMapLeft<T>(f: (value: L) => Either<T, R>): Either<null, R> | Either<T, R> {
    return this.isLeft ? f(this.left) : Either.right(this.right);
  }

  fold<T>(onLeft: (value: L) => T, onRight: (value: R) => T): T {
    return this.isLeft ? onLeft(this.left) : onRight(this.right);
  }

  getOrElse(defaultValue: R): R {
    return this.isRight ? this.right : defaultValue;
  }

  getLeftOrElse(defaultValue: L): L {
    return this.isLeft ? this.left : defaultValue;
  }

  getOrThrow(): R {
    return this.right;
  }

  getLeftOrThrow(exception: any): L {
    return this.isLeft ? this.left : exception;
  }

  getRightOrThrowLeft(): R {
    return this.isRight ? this.right : (this.left as any);
  }

  throwIfLeft(exception?: any): void {
    if (this.isLeft) {
      throw (
        exception ??
        (this.left instanceof Error
          ? this.left
          : new Error('Left value was raised intentionally ' + this.left?.toString()))
      );
    }
  }

  mapLeftVoid<T>(f: (value: L) => T): Either<T, null> {
    return Either.left(f(this.left));
  }

  toOption(): Option<R> {
    return this.isRight ? new Some(this.right) : new None();
  }

  toOptionLeft(): Option<L> {
    return this.isLeft ? new Some(this.left) : new None();
  }

  static conditional<L, R>(condition: boolean, { left, right }: { left: L; right: R }): Either<null, R> | Either<L, null> {
    return condition ? Either.right(right) : Either.left(left);
  }

  exists(predicate: (value: R) => boolean): boolean {
    return this.isRight ? predicate(this.right) : false;
  }

  toString(): string {
    return `Either{_left: ${this._left}, _right: ${this._right}}`;
  }
}

export class Some<T> implements Option<T> {
  constructor(public readonly value: T) {}

  get isDefined(): boolean {
    return true;
  }

  getOrElse(_defaultValue: T): T {
    return this.value;
  }

  getOrThrow(): T {
    return this.value;
  }

  map<U>(f: (t: T) => U): Option<U> {
    return new Some(f(this.value));
  }

  forEach(f: (t: T) => void): void {
    f(this.value);
  }

  flatMap<U>(f: (t: T) => Option<U>): Option<U> {
    return f(this.value);
  }

  fold<U>(onDefined: (t: T) => U, _onUndefined: () => U): U {
    return onDefined(this.value);
  }
}

export class None<T> implements Option<T> {
  get isDefined(): boolean {
    return false;
  }

  getOrElse(defaultValue: T): T {
    return defaultValue;
  }

  getOrThrow(exception: Error = new Error('Value is not defined.')): T {
    throw exception;
  }

  map<U>(_f: (t: T) => U): Option<U> {
    return new None<U>();
  }

  forEach(_f: (t: T) => void): void {}

  flatMap<U>(_f: (t: T) => Option<U>): Option<U> {
    return new None<U>();
  }

  fold<U>(_onDefined: (t: T) => U, onUndefined: () => U): U {
    return onUndefined();
  }
}

// export type Either<L, R> = { kind: 'Left'; value: L } | { kind: 'Right'; value: R };

export class EitherException extends Error {
  constructor(public readonly message: string) {
    super(message);
  }

  static rightIsUndefined() {
    return new EitherException('Right value is undefined!');
  }

  toString(): string {
    return `EitherException{message: ${this.message}}`;
  }
}

export class Unit {}
